#include "sched.h"
#include <linux/debugfs.h>


/* Macros and defines */
#define SCHED_PURGATORY_STATS
#define pr_info_purgatory(fmt, ...) \
	printk(KERN_INFO "[Purgatory] " pr_fmt(fmt), ##__VA_ARGS__)

#define trace_purgatory(cfs_rq, event, ts) trace_sched_purgatory_change((cfs_rq)->rq->cpu, (cfs_rq)->nr_running, (cfs_rq)->purgatory.nr, (cfs_rq)->purgatory.blocked_load, (cfs_rq)->load.weight, (cfs_rq)->avg.load_avg, (event), (ts));

#ifdef SCHED_PURGATORY_STATS
    #define inc_stat_field(name) \
        per_cpu_ptr(&pstats, smp_processor_id())->name++

    #define add_stat_field(name, inc) \
        per_cpu_ptr(&pstats, smp_processor_id())->name += inc
#else
    #define inc_stat_field(name)
    #define add_stat_field(name, inc)
#endif

#define lock_purgatory(__lock)
#define unlock_purgatory(__lock)

/* End of macros and defines */

/* Internal structures */
enum failed_add_type {
    PURGATORY_OFF = 0,
    TASK_NOT_SLEEPING,
    TIMESTAMP_SET,
    FAILED_ADD_END
};
struct purgatory_stats {
    u64 update_calls;
    u64 update_removed;
    u64 success_add;
    u64 failed_add[FAILED_ADD_END];
    u64 insert_calls;
    u64 remove_fails;
};

/* End of internal structures */

/* Internal varibles */
/*
    Purgatory controls.
    - @purgatory_on : Flag to activate/deactivate purgatory.
    - @purgatory_duration : How long a task should stay in the purgatory.
        Expressed in nanoseconds, default to 100 000ns.
    - @purgatory_clear_on_idle : Should we clear the purgatory on a
        runqueue when its core becomes idle.
*/
static __read_mostly bool purgatory_on = false;
static __read_mostly unsigned int purgatory_duration = 100000;
static __read_mostly bool purgatory_clear_on_idle = true;

static DEFINE_PER_CPU(struct purgatory_stats, pstats);

/* End of internal variables */

/* -----------  Set-up and init functions ----------- */
static int pshow(struct seq_file *m, void *p);
static int dump_rqs_info(struct seq_file *m, void *p);
static int dump_purgatory_cfg(struct seq_file *m, void *p);

static __init int init_purgatory_fs(void)
{
    debugfs_create_bool("purgatory_on", 0644, NULL, &purgatory_on);
    debugfs_create_bool("purgatory_clear_on_idle", 0644, NULL, &purgatory_clear_on_idle);
    debugfs_create_u32("purgatory_duration", 0644, NULL, &purgatory_duration);

#ifdef SCHED_PURGATORY_STATS 
    proc_create_single("pstats", 0644, NULL, pshow);
    proc_create_single("dump_rq", 0644, NULL, dump_rqs_info);
    proc_create_single("purgatory_configuration", 0644, NULL, dump_purgatory_cfg);
#endif

    pr_info_purgatory("Init OK");
    return 0;
}

late_initcall(init_purgatory_fs);
void purgatory_init_se(struct sched_entity *se)
{
    spin_lock_init(&se->purgatory.lock);
    INIT_LIST_HEAD(&se->purgatory.tasks);
    se->purgatory.blocked_timestamp = 0;
    se->purgatory.cfs_rq = NULL;
    se->purgatory.cpu_id = -1;
    se->purgatory.saved_load = 0;
    se->purgatory.out = 0;
}

void purgatory_init_cfs_rq(struct cfs_rq *cfs_rq)
{
	raw_spin_lock_init(&cfs_rq->purgatory.lock);
	INIT_LIST_HEAD(&cfs_rq->purgatory.tasks);
	cfs_rq->purgatory.nr = 0;
	cfs_rq->purgatory.blocked_load = 0;
}

/* Duplicated from fair.c as they are static */
static inline void update_load_add(struct load_weight *lw, unsigned long inc)
{
	lw->weight += inc;
	lw->inv_weight = 0;
}

static inline void update_load_sub(struct load_weight *lw, unsigned long dec)
{
	lw->weight -= dec;
	lw->inv_weight = 0;
}

/* Purgatory main functions */
int purgatory_activated(void)
{
    return purgatory_on;
}

int purgatory_do_clean_on_idle(void)
{
    return purgatory_clear_on_idle;
}

int purgatory_add_se(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
    ktime_t now;
    inc_stat_field(insert_calls);
    
    if (!purgatory_activated() || se->purgatory.blocked_timestamp || !(flags & DEQUEUE_SLEEP)) {

        if (!purgatory_activated()) {
            inc_stat_field(failed_add[PURGATORY_OFF]);
        } else if (se->purgatory.blocked_timestamp) {
            inc_stat_field(failed_add[TIMESTAMP_SET]);
        } else if (!(flags & DEQUEUE_SLEEP)) {
            inc_stat_field(failed_add[TASK_NOT_SLEEPING]);
        }

        return 0;
    }

    lockdep_assert_rq_held(cfs_rq->rq);

    // get_task_struct(task_of(se));

    now = ktime_get_ns();

    /* First we set-up se fields */
    se->purgatory.blocked_timestamp = now;
    se->purgatory.cfs_rq = cfs_rq;
    se->purgatory.out = 0;
    se->purgatory.saved_load = se->load.weight;

    /* Then we set-up rq fields */
    lock_purgatory(&cfs_rq->purgatory.lock);
    list_add_tail(&se->purgatory.tasks, &cfs_rq->purgatory.tasks);
    cfs_rq->purgatory.nr++;
    cfs_rq->purgatory.blocked_load += se->purgatory.saved_load;
    unlock_purgatory(&cfs_rq->purgatory.lock);
    trace_purgatory(cfs_rq, 0, now);
    return 1;
}

/*
    This function will remove @se from the purgatory of @cfs_rq
    without doing any tests so be carefull (esp. for the lock on 
    @cfs_rq).
*/
void purgatory_remove_se(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
    update_load_sub(&cfs_rq->load, se->purgatory.saved_load);
    cfs_rq->purgatory.blocked_load -= se->purgatory.saved_load;
    cfs_rq->purgatory.nr--;

    se->purgatory.blocked_timestamp = 0;
    se->purgatory.saved_load = 0;
    se->purgatory.cfs_rq = NULL;
    se->purgatory.out = 0;

    list_del(&se->purgatory.tasks);
    // put_task_struct(task_of(se));
}

/*
    Helper function to test if we can remove @se if it has 
    exceeded the maximum duration in the purgatory state.
*/
inline int purgatory_can_remove_se(struct sched_entity *se, ktime_t now)
{
    return (now - se->purgatory.blocked_timestamp) > purgatory_duration;
}

int purgatory_try_to_remove_se(struct cfs_rq *cfs_rq, struct sched_entity *se,
                ktime_t now)
{
    if (!se->purgatory.blocked_timestamp)
        return 0;

    // lockdep_assert_rq_held(cfs_rq->rq);

    if (purgatory_can_remove_se(se, now)) {
        purgatory_remove_se(cfs_rq, se);
    } else {
        return 0;
    }

    trace_purgatory(cfs_rq, 0, now);
    return 1;
}


/*
    Main update function. This will iterate through the 
    list of tasks if the purgatory is not empty.
    In order to not go through the whole list, we rely on 
    the insertion order. It means that if a task T_1 has not
    spend more than @purgatory_duration in the purgatory of 
    @cfs_rq, the tasks inserted later have not too.

    - @cfs_rq : The runqueue to update

    returns : Number of tasks effectivly removed from the purgatory.
*/
int purgatory_update(struct cfs_rq *cfs_rq)
{
    struct sched_entity *pos, *tmp;
    int nr_removed = 0;
    ktime_t now;
    /* 
        Here we don't check if the purgatory if deactivated
        because if do deactivate it and some tasks remain
        in it, we need to remove them.
    */
    if (!cfs_rq->purgatory.nr)
        return 0;


    inc_stat_field(update_calls);
    // lockdep_assert_rq_held(rq_of(cfs_rq));
    now = ktime_get_ns();
    lock_purgatory(&cfs_rq->purgatory.lock);
    list_for_each_entry_safe(pos, tmp, &cfs_rq->purgatory.tasks, purgatory.tasks) {
        if (purgatory_try_to_remove_se(cfs_rq, pos, now)) {
            nr_removed++;
        } else {
            break;
        }
    }
    unlock_purgatory(&cfs_rq->purgatory.lock);
    trace_purgatory(cfs_rq, 0, now);
    add_stat_field(update_removed, nr_removed);

    return nr_removed;
}

/*
    This function clears the purgatory. Meaning it empties it
*/
void purgatory_clear(struct cfs_rq *cfs_rq)
{
    struct sched_entity *pos, *tmp;
    
    // lockdep_assert_rq_held(cfs_rq->rq);
    if (!cfs_rq->purgatory.nr)
        return;
    lock_purgatory(&cfs_rq->purgatory.lock);
    list_for_each_entry_safe(pos, tmp, &cfs_rq->purgatory.tasks, purgatory.tasks) {
        purgatory_remove_se(cfs_rq, pos);
    }
    unlock_purgatory(&cfs_rq->purgatory.lock);
    trace_purgatory(cfs_rq, 0, ktime_get_ns());
}

inline void purgatory_task_dead(struct task_struct *p)
{
	// struct rq_flags rf;
	// int do_lock = 0;
	struct sched_entity *se = &p->se;
	// struct cfs_rq *cfs_rq = se->purgatory.cfs_rq;
	/* Si nous sommes dans le purgatoire */
	if (se->purgatory.blocked_timestamp) {
        // lock_purgatory(&cfs_rq->purgatory.lock);
        purgatory_remove_se(se->purgatory.cfs_rq, se);
        // unlock_purgatory(&cfs_rq->purgatory.lock);
	}
}

/* Debug functions */
static int pshow(struct seq_file *m, void *p)
{
	struct purgatory_stats *curr_stats;
	int cpu;
	seq_printf(m,"t=%llu\n;v=%s", ktime_get_ns(), CONFIG_LOCALVERSION);
	
	for_each_possible_cpu(cpu) {
		curr_stats = per_cpu_ptr(&pstats, cpu);
		seq_printf(m, "+--------------------+\n");

        // seq_printf
	}
	return 0;
}
static int dump_rqs_info(struct seq_file *m, void *p)
{
    int cpu;
    struct cfs_rq *rq;
    for_each_possible_cpu(cpu) {
        rq = &cpu_rq(cpu)->cfs;
        seq_printf(m, "+--------------------+\n");
        seq_printf(m, "cpu %d\n", cpu);
        seq_printf(m, "avg_load %lu\n", rq->avg.load_avg);
        seq_printf(m, "weight %lu\n", rq->load.weight);
        seq_printf(m, "blocked_load %lu\n", rq->purgatory.blocked_load);
        seq_printf(m, "h_load %lu\n", rq->h_load);
        seq_printf(m, "nr_purgatory %lu\n", rq->purgatory.nr);
        seq_printf(m, "nr_running %d\n", rq->nr_running);
        seq_printf(m, "h_nr_running %d\n", rq->h_nr_running);

    }

    return 0;
}

static int dump_purgatory_cfg(struct seq_file *m, void *p)
{
    seq_printf(m, "Purgatory version :\n");
    seq_printf(m, "purgatory_duration : %d", purgatory_duration);
    seq_printf(m, "clear_on_idle : %d", purgatory_clear_on_idle);

    return 0;
}
/* End of debug functions */