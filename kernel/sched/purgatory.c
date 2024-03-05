#include "sched.h"
#include <linux/debugfs.h>


/* Macros and defines */
/*
 * SCHED_PURGATORY_STATS : If set, allow stats for the purgatory
 * SCHED_PURGATORY_SHADOW : Everyhting happens in the purgatory except we do not update
    the load.
*/

#define SCHED_PURGATORY_DEBUG 
#define SCHED_PURGATORY_STATS
#define SCHED_PURGATORY_SHADOW 0
/* #define pr_info_purgatory(fmt, ...) \
	printk(KERN_INFO "[Purgatory] " pr_fmt(fmt), ##__VA_ARGS__) */

#define pr_info_purgatory(fmt, ...) 
// #define trace_purgatory(cfs_rq, event, ts) trace_sched_purgatory_change((cfs_rq)->rq->cpu, (cfs_rq)->nr_running, (cfs_rq)->purgatory.nr, (cfs_rq)->purgatory.blocked_load, (cfs_rq)->load.weight, (cfs_rq)->avg.load_avg, (event), (ts));
#define trace_purgatory(cfs_rq, event, ts)

#define trace_purgatory_load(cfs_rq) trace_sched_purgatory_load((cfs_rq)->rq->cpu, (cfs_rq)->load.weight, (cfs_rq)->purgatory.blocked_load, (cfs_rq)->avg.load_avg, (cfs_rq)->purgatory.blocked_avg_load, (cfs_rq)->nr_running, (cfs_rq)->purgatory.nr)

#define trace_purgatory_size(cfs_rq) trace_sched_purgatory_size((cfs_rq)->rq->cpu, (cfs_rq)->nr_running, (cfs_rq)->purgatory.nr)

#ifdef SCHED_PURGATORY_STATS
    #define inc_stat_field(name) \
        per_cpu_ptr(&pstats, smp_processor_id())->name++

    #define add_stat_field(name, inc) \
        per_cpu_ptr(&pstats, smp_processor_id())->name += inc
#else
    #define inc_stat_field(name)
    #define add_stat_field(name, inc)
#endif

/* End of macros and defines */

/* Internal structures */
enum failed_add_type {
    PURGATORY_OFF = 0,
    TASK_NOT_SLEEPING,
    TIMESTAMP_SET,
    TAGGED_BY_REMOTE,
    FAILED_ADD_END
};
struct purgatory_stats {
    u64 update_calls;
    u64 update_removed;
    u64 update_too_soon;
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
static __read_mostly bool purgatory_clear_on_idle = false;
static __read_mostly u64 purgatory_update_delta_ns = 100000;

static DEFINE_PER_CPU(struct purgatory_stats, pstats);


ssize_t purgatory_on_fs_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;
	
	ret = debugfs_write_file_bool(file, user_buf, count, ppos);
	return ret;
}
static const struct file_operations fops_purgatory_on = {
    .write = purgatory_on_fs_write,
    .read = debugfs_read_file_bool,
    .open = simple_open,
    .llseek = default_llseek
};


ssize_t purgatory_clear_fs_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	ssize_t ret;
    int cpu;
    struct rq_flags rf;
    for_each_possible_cpu(cpu) {
        struct rq *rq = cpu_rq(cpu);
        rq_lock_irq(rq, &rf);
        purgatory_clear(&rq->cfs);
        rq_unlock_irq(rq, &rf);
    }

	ret = debugfs_write_file_bool(file, user_buf, count, ppos);
	return ret;
}

static const struct file_operations fops_purgatory_clear = {
    .write = purgatory_clear_fs_write,
    .read = debugfs_read_file_bool,
    .open = simple_open,
    .llseek = default_llseek
};

static bool clear_purgatory_debugfs = false;
/* End of internal variables */

/* -----------  Set-up and init functions ----------- */
static int pshow(struct seq_file *m, void *p);
static int dump_rqs_info(struct seq_file *m, void *p);
static int dump_purgatory_cfg(struct seq_file *m, void *p);

static __init int init_purgatory_fs(void)
{
    debugfs_create_file("purgatory_on", 0644, NULL, &purgatory_on,
        &fops_purgatory_on);
    debugfs_create_bool("purgatory_clear_on_idle", 0644, NULL, &purgatory_clear_on_idle);
    debugfs_create_u32("purgatory_duration", 0644, NULL, &purgatory_duration);
    debugfs_create_file("purgatory_clear", 0644, NULL, &clear_purgatory_debugfs,
        &fops_purgatory_clear);
#ifdef SCHED_PURGATORY_STATS 
    proc_create_single("pstats", 0644, NULL, pshow);
    proc_create_single("dump_rq", 0644, NULL, dump_rqs_info);
    proc_create_single("purgatory_configuration", 0644, NULL, dump_purgatory_cfg);
#endif

    pr_info_purgatory("Init OK");
    return 0;
}

late_initcall(init_purgatory_fs);
/*
    Initializes @se->purgatory fields.

    Called in :
        - __sched_fork
*/
void purgatory_init_se(struct sched_entity *se)
{
    INIT_LIST_HEAD(&se->purgatory.tasks);
    se->purgatory.blocked_timestamp = 0;
    se->purgatory.cfs_rq = NULL;
    se->purgatory.saved_load = 0;
    se->purgatory.out = 0;
    se->purgatory.saved_avg_load = 0;
    se->purgatory.stats.added = 0;
    se->purgatory.stats.left_early = 0;
    se->purgatory.stats.timed_out = 0;
    se->purgatory.stats.removed_by_clear = 0;
}

/*
    Initializes @cfs->purgatory fields.

    Called in :
  ²      - init_cfs_rq
*/
void purgatory_init_cfs_rq(struct cfs_rq *cfs_rq)
{

	INIT_LIST_HEAD(&cfs_rq->purgatory.tasks);
	cfs_rq->purgatory.nr = 0;
	cfs_rq->purgatory.blocked_load = 0;
    cfs_rq->purgatory.next_update = jiffies;
}

/* Duplicated from fair.c as they are static */
static inline void update_load_add(struct load_weight *lw, unsigned long inc)
{
#if SCHED_PURGATORY_SHADOW == 0
	lw->weight += inc;
	lw->inv_weight = 0;
#endif
}

static inline void update_load_sub(struct load_weight *lw, unsigned long dec)
{
#if  SCHED_PURGATORY_SHADOW == 0
	lw->weight -= dec;
	lw->inv_weight = 0;
#endif
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

/*
    Add @se to the purgatory of @cfs runqueue.

    Returns :
        - 1 : if the tasks was added.
        - 0 : if not.
    Called in :
        - dequeue_task_fair

    Requirements :
        - locks : old the cfs_rq->rq lock
*/
int purgatory_add_se(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
    __must_hold(cfs_rq->rq->__lock)
{
    u64 now;
    inc_stat_field(insert_calls);


    if (!purgatory_activated() || se->purgatory.blocked_timestamp || !(flags & DEQUEUE_SLEEP) || se->purgatory.out) {

        if (!purgatory_activated()) {
            inc_stat_field(failed_add[PURGATORY_OFF]);
        } else if (se->purgatory.blocked_timestamp) {
            inc_stat_field(failed_add[TIMESTAMP_SET]);
        } else if (!(flags & DEQUEUE_SLEEP)) {
            inc_stat_field(failed_add[TASK_NOT_SLEEPING]);
        } else if(se->purgatory.out) {
            inc_stat_field(failed_add[TAGGED_BY_REMOTE]);
        }
        return 0;
    }

    lockdep_assert_rq_held(cfs_rq->rq);

    now = rq_clock(cfs_rq->rq);

    /* First we set-up se fields */
    se->purgatory.blocked_timestamp = now;
    se->purgatory.cfs_rq = cfs_rq;
    se->purgatory.saved_avg_load = se->avg.load_avg;
    se->purgatory.saved_load = se->load.weight;
    update_load_add(&cfs_rq->load, se->purgatory.saved_load);

    /* Then we set-up rq fields */
    list_add_tail(&se->purgatory.tasks, &cfs_rq->purgatory.tasks);
    cfs_rq->purgatory.blocked_avg_load = se->purgatory.saved_avg_load;    
    cfs_rq->purgatory.nr++;
    cfs_rq->purgatory.blocked_load += se->purgatory.saved_load;

    se->purgatory.stats.added++;
    inc_stat_field(success_add);
    trace_purgatory_size(cfs_rq);
    return 1;
}

/*
    This function will remove @se from the purgatory of @cfs_rq
    without doing any tests so be carefull (esp. for the lock on 
    @cfs_rq).

    Called in :
        - purgatory_try_to_remove
        - purgatory_clear
        - dequeue_task_fair
    Requirements :
        - locks : old the @cfs_rq->rq lock²
*/
void purgatory_remove_se(struct cfs_rq *cfs_rq, struct sched_entity *se)
    __must_hold(cfs_rq->rq->__lock)
{

    if (cfs_rq != se->purgatory.cfs_rq){
        se->purgatory.out = 1;
        return;
    }

    lockdep_assert_rq_held(cfs_rq->rq);

    update_load_sub(&cfs_rq->load, se->purgatory.saved_load);
    cfs_rq->purgatory.blocked_load -= se->purgatory.saved_load;
    cfs_rq->purgatory.nr--;
    cfs_rq->purgatory.blocked_avg_load -= se->purgatory.saved_avg_load;

    se->purgatory.saved_avg_load = 0;
    se->purgatory.blocked_timestamp = 0;
    se->purgatory.saved_load = 0;
    se->purgatory.cfs_rq = NULL;

    list_del_init_careful(&se->purgatory.tasks);
    trace_purgatory_size(cfs_rq);
}

/*
    Helper function to test if we can remove @se if it has 
    exceeded the maximum duration in the purgatory state.
    
    Returns:
        - 1 : if the tasks has exceeded the maximum time in the 
            purgatory.
        - 0 : if not
        
    Called in :
        - purgatory_try_to_remove_se
    
    Requirements : None
*/
inline int purgatory_can_remove_se(struct sched_entity *se, u64 now)
{
    return se->purgatory.out || (now - se->purgatory.blocked_timestamp) > purgatory_duration;
}

/*
    Tries to remove a task @se from the purgatory. It will we removed 
    iif 
        @se->purgatory.cfs == @cfs_rq && \
        (@now - @se->purgatory.blocked_timestamp) > purgatory_duration

    Return :
        1 : If it was removed.
        0 : If not.
*/
int purgatory_try_to_remove_se(struct cfs_rq *cfs_rq, struct sched_entity *se,
                u64 now)
{
    if (!se->purgatory.blocked_timestamp)
        return 0;

    lockdep_assert_rq_held(cfs_rq->rq);

#ifdef SCHED_PURGATORY_DEBUG
    if (se->purgatory.cfs_rq != cfs_rq) {
        pr_info("se->purgatory.cfs_rq != cfs_rq\n");
        BUG();
    }
        
#endif

    if (purgatory_can_remove_se(se, now)) {
        purgatory_remove_se(cfs_rq, se);
    } else {
        return 0;
    }

    trace_purgatory(cfs_rq, 0, now);
    return 1;
}

void purgatory_do_task_dead(struct task_struct *p)
{
    struct rq_flags rf;
    struct  sched_entity *se = &p->se;
    struct cfs_rq *cfs_rq = se->purgatory.cfs_rq;
    if (!se->purgatory.blocked_timestamp)
        return;
    rq_lock_irq(rq_of(cfs_rq), &rf);
    purgatory_remove_se(cfs_rq, se);
    rq_unlock_irq(rq_of(cfs_rq), &rf);

    trace_purgatory_size(cfs_rq);
    // se->purgatory.stats.timed_out++;

}

/*
    Main update function. This will iterate through the 
    list of tasks if the purgatory is not empty.
    In order to not go through the whole list, we rely on 
    the insertion order. It means that if a task T_1 has not
    spend more than @purgatory_duration in the purgatory of 
    @cfs_rq, the tasks inserted later won't have.

    - @cfs_rq : The runqueue to update

    Return :
        - The number of tasks removed from the purgatory

    Called in :
        - 

    Requirements :
        - @cfs_rq->rq->__lock must be held.
*/
int purgatory_update(struct cfs_rq *cfs_rq)
    __must_hold(cfs_rq->rq->__lock)
{
    struct sched_entity *pos, *tmp;
    int nr_removed = 0;
    u64 now = rq_clock(cfs_rq->rq);


    /* 
        Here we don't check if the purgatory if deactivated
        because if do deactivate it and some tasks remain
        in it, we need to remove them.
    */
    if (!cfs_rq->purgatory.nr || !purgatory_activated() || now < cfs_rq->purgatory.next_update) {
        if (now < cfs_rq->purgatory.next_update)
            inc_stat_field(update_too_soon);

        return 0;
    }


    inc_stat_field(update_calls);
    
    lockdep_assert_rq_held(rq_of(cfs_rq));
    
    list_for_each_entry_safe(pos, tmp, &cfs_rq->purgatory.tasks, purgatory.tasks) {
        if (purgatory_try_to_remove_se(cfs_rq, pos, now)) {
            pos->purgatory.stats.timed_out++;
            nr_removed++;
        } else {
            break;
        }
    }

    add_stat_field(update_removed, nr_removed);
    
    cfs_rq->purgatory.next_update = now + (nr_removed ? purgatory_update_delta_ns : purgatory_update_delta_ns * 2);
    trace_sched_purgatory_update_stats(nr_removed);
    return nr_removed;
}

/*
    This function empties the purgatory of @cfs_rq.

    Called in:
        - balance_fair
    
    Requirements:
        - @cfs_rq->rq->__lock must be held.
*/
void purgatory_clear(struct cfs_rq *cfs_rq)
    __must_hold(cfs_rq->rq->__lock)
{
    struct sched_entity *pos, *tmp;
    unsigned long nr_removed = 0;

    lockdep_assert_rq_held(cfs_rq->rq);

    if (!cfs_rq->purgatory.nr)
        return;

    list_for_each_entry_safe(pos, tmp, &cfs_rq->purgatory.tasks, purgatory.tasks) {
        pos->purgatory.stats.removed_by_clear++;
        purgatory_remove_se(cfs_rq, pos);
        nr_removed++;
    }
    trace_sched_purgatory_clear_stats(nr_removed);
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
        seq_printf(m, "update calls    : %llu\n", curr_stats->update_calls);
        seq_printf(m, "update removed  : %llu\n", curr_stats->update_removed);
        seq_printf(m, "update too soon : %llu\n", curr_stats->update_too_soon);
        seq_printf(m, "insert calls : %llu\n", curr_stats->insert_calls);
        seq_printf(m, "insert err. ts set : %llu\n", curr_stats->failed_add[TIMESTAMP_SET]);
        seq_printf(m, "insert err. not sleeping : %llu\n", curr_stats->failed_add[TASK_NOT_SLEEPING]);
        seq_printf(m, "insert err. tagged remote : %llu\n", curr_stats->failed_add[TAGGED_BY_REMOTE]);
        seq_printf(m, "success add : %llu\n", curr_stats->success_add);

        

        
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
        seq_printf(m, "purgatory.next_update %llu\n", rq->purgatory.next_update);
        seq_printf(m, "purgatory.tasks %p\n", &rq->purgatory.tasks);
        seq_printf(m, "purgatory.tasks.next %p\n", rq->purgatory.tasks.next);
        seq_printf(m, "purgatory.tasks.prev %p\n", rq->purgatory.tasks.prev);

    }

    return 0;
}

static int dump_purgatory_cfg(struct seq_file *m, void *p)
{
    seq_printf(m, "Purgatory version :\n");
    seq_printf(m, "purgatory_duration : %d\t", purgatory_duration);
    seq_printf(m, "clear_on_idle : %d\t", purgatory_clear_on_idle);
    return 0;
}
/* End of debug functions */