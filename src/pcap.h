#define FFI_SCOPE "_RTCKIT_PCAP_FFI_"
#define FFI_LIB   "libpcap.so.1"

typedef unsigned long int time_t;
typedef unsigned long int suseconds_t;

typedef struct timeval {
    time_t tv_sec;
    suseconds_t tv_usec;
} timeval_t;

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef int sig_atomic_t;
typedef uint32_t bpf_u_int32;

typedef enum {
    PCAP_D_INOUT = 0,
    PCAP_D_IN,
    PCAP_D_OUT
} pcap_direction_t;

typedef struct bpf_program {
    u_int bf_len;
    struct bpf_insn *bf_insns;
} bpf_program_t;

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

typedef struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
} pcap_addr_t;

typedef struct pcap_if {
    struct pcap_if *next;
    char *name;
    char *description;
    pcap_addr_t *addresses;
    bpf_u_int32 flags;
} pcap_if_t;

typedef struct pcap_samp {
    int method;
    int value;
} pcap_samp_t;

typedef struct pcap pcap_t;

typedef int (*activate_op_t)(pcap_t *);
typedef int (*can_set_rfmon_op_t)(pcap_t *);
typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
typedef int (*read_op_t)(pcap_t *, int cnt, pcap_handler, u_char *);
typedef int (*next_packet_op_t)(pcap_t *, struct pcap_pkthdr *, u_char **);
typedef int (*inject_op_t)(pcap_t *, const void *, int);
typedef void (*save_current_filter_op_t)(pcap_t *, const char *);
typedef int (*setfilter_op_t)(pcap_t *, struct bpf_program *);
typedef int (*setdirection_op_t)(pcap_t *, pcap_direction_t);
typedef int (*set_datalink_op_t)(pcap_t *, int);
typedef int (*getnonblock_op_t)(pcap_t *);
typedef int (*setnonblock_op_t)(pcap_t *, int);
typedef int (*stats_op_t)(pcap_t *, struct pcap_stat *);
typedef void (*breakloop_op_t)(pcap_t *);
typedef void (*cleanup_op_t)(pcap_t *);

typedef struct pcap_opt {
    char *device;
    int timeout;
    u_int buffer_size;
    int promisc;
    int rfmon;
    int immediate;
    int nonblock;
    int tstamp_type;
    int tstamp_precision;
    int protocol;
} pcap_opt_t;

typedef struct pcap_stat {
    u_int ps_recv;
    u_int ps_drop;
    u_int ps_ifdrop;
} pcap_stat_t;

typedef struct pcap {
    read_op_t read_op;
    next_packet_op_t next_packet_op;
    int fd;
    u_int bufsize;
    void *buffer;
    u_char *bp;
    int cc;
    sig_atomic_t break_loop;
    void *priv;
    struct pcap_samp rmt_samp;
    int swapped;
    void *rfile;
    u_int fddipad;
    struct pcap *next;
    int version_major;
    int version_minor;
    int snapshot;
    int linktype;
    int linktype_ext;
    int offset;
    int activated;
    int oldstyle;
    struct pcap_opt opt;
    u_char *pkt;
    pcap_direction_t direction;
    int bpf_codegen_flags;
    int selectable_fd;
    const struct timeval *required_select_timeout;
    struct bpf_program fcode;
    char errbuf[257];
    int dlt_count;
    u_int *dlt_list;
    int tstamp_type_count;
    u_int *tstamp_type_list;
    int tstamp_precision_count;
    u_int *tstamp_precision_list;
    struct pcap_pkthdr pcap_header;
    activate_op_t activate_op;
    can_set_rfmon_op_t can_set_rfmon_op;
    inject_op_t inject_op;
    save_current_filter_op_t save_current_filter_op;
    setfilter_op_t setfilter_op;
    setdirection_op_t setdirection_op;
    set_datalink_op_t set_datalink_op;
    getnonblock_op_t getnonblock_op;
    setnonblock_op_t setnonblock_op;
    stats_op_t stats_op;
    breakloop_op_t breakloop_op;
    pcap_handler oneshot_callback;
    cleanup_op_t cleanup_op;
};

const char *pcap_lib_version(void);
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);
pcap_t *pcap_create(const char *source, char *errbuf);
char *pcap_geterr(pcap_t *p);
int pcap_set_snaplen(pcap_t *p, int snaplen);
int pcap_set_promisc(pcap_t *p, int promisc);
int pcap_set_immediate_mode(pcap_t *p, int immediate_mode);
int pcap_set_timeout(pcap_t *p, int to_ms);
int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf);
int pcap_activate(pcap_t *p);
int pcap_get_selectable_fd(pcap_t *p);
int pcap_inject(pcap_t *p, const void *buf, size_t size);
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
void pcap_close(pcap_t *p);
