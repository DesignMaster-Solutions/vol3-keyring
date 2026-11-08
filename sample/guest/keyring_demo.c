/*
 * Benign workload for the vol3-keyring memory sample. Each mode builds a known set of kernel keys with the
 * keyctl(2) family of system calls, prints them as ground truth on the console (TRUTH lines), and then idles
 * so the keys are resident when the guest is dumped. On SIGUSR1 a process prints /proc/keys as it sees it
 * (the kernel only shows the keys the reader may view, so every owner prints its own view).
 *
 * The payloads are made-up strings. Nothing is read from the system, nothing talks to the network.
 *
 *   keyring_demo alice     uid 1000: session/process/thread/user keyrings, user + logon keys, nested keyrings,
 *                          and a second thread with its own thread keyring
 *   keyring_demo bob       uid 1001: a key linked from two keyrings, revoked, expired and 3-day keys,
 *                          a keyring with 40 keys (assoc_array nodes) and one with 20 keyrings (shortcut)
 *   keyring_demo orphan    root: joins a named keyring as its session and unlinks it from every keyring
 *   keyring_demo carol     root: one request_key() that the helper rejects (negative key) and one that stays
 *                          under construction (helper holds the authorisation key)
 *   keyring_demo empty     no keyrings at all
 *   request-key ...        /sbin/request-key, the helper the kernel runs for request_key() (see carol)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/keyctl.h>
#include <sys/syscall.h>

static const char *tag = "?";
static volatile sig_atomic_t want_view;

static long kctl(long op, long a, long b, long c, long d) { return syscall(SYS_keyctl, op, a, b, c, d); }

static int add(const char *type, const char *desc, const void *data, size_t len, int ring)
{
    long id = syscall(SYS_add_key, type, desc, data, len, ring);
    if (id < 0) { fprintf(stderr, "%s: add_key %s %s: %s\n", tag, type, desc, strerror(errno)); exit(1); }
    return (int)id;
}

static void ok(long rc, const char *what)
{
    if (rc < 0) { fprintf(stderr, "%s: %s: %s\n", tag, what, strerror(errno)); exit(1); }
}

/* TRUTH key <tag> serial=<hex> where=<where> desc=<type;uid;gid;perm;description> */
static void truth_key(int id, const char *where)
{
    char d[512];
    long n = kctl(KEYCTL_DESCRIBE, id, (long)d, sizeof d, 0);
    printf("TRUTH key %s serial=%08x where=%s desc=%s\n", tag, id, where, n < 0 ? strerror(errno) : d);
}

/* What user space gets back from KEYCTL_READ: the payload for user keys, serials for keyrings, an error for logon. */
static void truth_read(int id, const char *kind)
{
    unsigned char b[4096];
    long n = kctl(KEYCTL_READ, id, (long)b, sizeof b, 0);
    if (n < 0) { printf("TRUTH read %s serial=%08x error=%s\n", tag, id, strerror(errno)); return; }
    if (n > (long)sizeof b) n = sizeof b;
    if (!strcmp(kind, "ring")) {
        printf("TRUTH members %s serial=%08x n=%ld", tag, id, n / 4);
        for (long i = 0; i < n / 4; i++) printf(" %08x", ((int *)b)[i]);
    } else {
        printf("TRUTH read %s serial=%08x len=%ld hex=", tag, id, n);
        for (long i = 0; i < n; i++) printf("%02x", b[i]);
    }
    printf("\n");
}

/* The payload as the guest wrote it, for keys user space cannot read back (logon). */
static void truth_written(int id, const void *data, size_t len)
{
    printf("TRUTH written %s serial=%08x len=%zu hex=", tag, id, len);
    for (size_t i = 0; i < len; i++) printf("%02x", ((const unsigned char *)data)[i]);
    printf("\n");
}

static void truth_rings(void)
{
    static const struct { int spec; const char *name; } r[] = {
        { KEY_SPEC_THREAD_KEYRING, "thread" }, { KEY_SPEC_PROCESS_KEYRING, "process" },
        { KEY_SPEC_SESSION_KEYRING, "session" }, { KEY_SPEC_USER_KEYRING, "user" },
        { KEY_SPEC_USER_SESSION_KEYRING, "user_session" },
    };
    printf("TRUTH proc %s pid=%d tid=%ld uid=%d", tag, getpid(), syscall(SYS_gettid), getuid());
    for (size_t i = 0; i < sizeof r / sizeof r[0]; i++) {
        long id = kctl(KEYCTL_GET_KEYRING_ID, r[i].spec, 0, 0, 0);
        if (id < 0) printf(" %s=none", r[i].name); else printf(" %s=%08lx", r[i].name, id);
    }
    printf("\n");
}

static void on_usr1(int s) { (void)s; want_view = 1; }

static void print_view(void)
{
    char line[1024];
    FILE *f = fopen("/proc/keys", "r");
    if (!f) { printf("TRUTH view %s error=%s\n", tag, strerror(errno)); return; }
    while (fgets(line, sizeof line, f)) printf("TRUTH view %s %s", tag, line);
    fclose(f);
    printf("TRUTH viewend %s pid=%d\n", tag, getpid());
}

static void idle(void)
{
    fflush(stdout);
    for (;;) {
        pause();
        if (want_view) { want_view = 0; print_view(); fflush(stdout); }
    }
}

/* SIGUSR1 must reach the main thread, which is the one that prints the view. */
static void block_usr1(void)
{
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &m, NULL);
}

static void become(int uid)
{
    ok(setresgid(uid, uid, uid), "setresgid");
    ok(setresuid(uid, uid, uid), "setresuid");
}

static void *alice_worker(void *arg)
{
    (void)arg;
    block_usr1();
    const char v[] = "worker-thread-note";
    int k = add("user", "alice:worker-thread", v, sizeof v - 1, KEY_SPEC_THREAD_KEYRING);
    truth_key(k, "@t");
    truth_rings();
    fflush(stdout);
    for (;;) pause();
    return NULL;
}

static int mode_alice(void)
{
    become(1000);
    int ses = (int)kctl(KEYCTL_JOIN_SESSION_KEYRING, (long)"alice-session", 0, 0, 0);
    ok(ses, "join alice-session");
    const char tok[] = "alice-token-0001";
    const char vol[] = "LUKS-DEMO-VOLUME-KEY-0123456789ab"; /* 32 bytes + made up, like a dm-crypt volume key */
    const char ps[] = "process-only-secret", tn[] = "thread-note", uk[] = "uid-keyring-key", deep[] = "two-levels-down";
    int k1 = add("user", "alice:token", tok, sizeof tok - 1, KEY_SPEC_SESSION_KEYRING);
    int k2 = add("logon", "cryptsetup:alice-vol", vol, 32, KEY_SPEC_SESSION_KEYRING);
    int r1 = add("keyring", "alice-ring1", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    int r2 = add("keyring", "alice-ring2", NULL, 0, r1);
    int k3 = add("user", "alice:deep", deep, sizeof deep - 1, r2);
    int k4 = add("user", "alice:proc-secret", ps, sizeof ps - 1, KEY_SPEC_PROCESS_KEYRING);
    int k5 = add("user", "alice:thread-note", tn, sizeof tn - 1, KEY_SPEC_THREAD_KEYRING);
    int k6 = add("user", "alice:uid-key", uk, sizeof uk - 1, KEY_SPEC_USER_KEYRING);
    truth_key(ses, "session");
    truth_key(k1, "@s"); truth_read(k1, "user");
    truth_key(k2, "@s"); truth_read(k2, "logon"); truth_written(k2, vol, 32);
    truth_key(r1, "@s"); truth_key(r2, "alice-ring1"); truth_key(k3, "alice-ring2"); truth_read(k3, "user");
    truth_key(k4, "@p"); truth_key(k5, "@t"); truth_key(k6, "@u");
    truth_rings();
    pthread_t t;
    if (pthread_create(&t, NULL, alice_worker, NULL)) { fprintf(stderr, "pthread_create\n"); return 1; }
    usleep(300000);
    truth_read(ses, "ring"); truth_read(r1, "ring"); truth_read(r2, "ring");
    truth_read((int)kctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 0, 0, 0), "ring");
    idle();
    return 0;
}

static int mode_bob(void)
{
    become(1001);
    int ses = (int)kctl(KEYCTL_JOIN_SESSION_KEYRING, (long)"bob-session", 0, 0, 0);
    ok(ses, "join bob-session");
    const char cfg[] = "mode=demo;interval=60", rv[] = "revoked-value", ex[] = "expires-in-1s", d3[] = "three-days";
    int shared = add("user", "shared:config", cfg, sizeof cfg - 1, KEY_SPEC_SESSION_KEYRING);
    int proc = (int)kctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 1, 0, 0);
    ok(proc, "create process keyring");
    ok(kctl(KEYCTL_LINK, shared, proc, 0, 0), "link shared into @p");
    int rk = add("user", "bob:revoked", rv, sizeof rv - 1, KEY_SPEC_SESSION_KEYRING);
    ok(kctl(KEYCTL_REVOKE, rk, 0, 0, 0), "revoke");
    int xk = add("user", "bob:expired", ex, sizeof ex - 1, KEY_SPEC_SESSION_KEYRING);
    ok(kctl(KEYCTL_SET_TIMEOUT, xk, 1, 0, 0), "timeout 1");
    int dk = add("user", "bob:3days", d3, sizeof d3 - 1, KEY_SPEC_SESSION_KEYRING);
    ok(kctl(KEYCTL_SET_TIMEOUT, dk, 3 * 86400, 0, 0), "timeout 3d");
    int many = add("keyring", "bob-many-keys", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    int rings = add("keyring", "bob-many-rings", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    char d[32], v[32];
    for (int i = 0; i < 40; i++) {
        snprintf(d, sizeof d, "bob:many-%02d", i);
        snprintf(v, sizeof v, "value-%02d", i);
        truth_key(add("user", d, v, strlen(v), many), "bob-many-keys");
    }
    for (int i = 0; i < 20; i++) {
        snprintf(d, sizeof d, "bob-sub-%02d", i);
        truth_key(add("keyring", d, NULL, 0, rings), "bob-many-rings");
    }
    truth_key(ses, "session"); truth_key(proc, "process");
    truth_key(shared, "@s+@p"); truth_read(shared, "user");
    truth_key(rk, "@s"); truth_read(rk, "user");
    truth_key(dk, "@s");
    truth_key(many, "@s"); truth_key(rings, "@s");
    sleep(2);
    truth_key(xk, "@s"); truth_read(xk, "user");
    truth_rings();
    truth_read(ses, "ring"); truth_read(proc, "ring"); truth_read(many, "ring"); truth_read(rings, "ring");
    idle();
    return 0;
}

static int mode_orphan(void)
{
    const char held[] = "only-reachable-through-cred";
    int ring = add("keyring", "detached-ring", NULL, 0, KEY_SPEC_USER_KEYRING);
    int k = add("user", "orphan:held", held, sizeof held - 1, ring);
    /* join_session_keyring() only finds a named keyring the caller may search without possessing it. */
    ok(kctl(KEYCTL_SETPERM, ring, 0x3f3f0000, 0, 0), "setperm detached-ring");
    ok(kctl(KEYCTL_JOIN_SESSION_KEYRING, (long)"detached-ring", 0, 0, 0), "join detached-ring");
    ok(kctl(KEYCTL_UNLINK, ring, KEY_SPEC_USER_KEYRING, 0, 0), "unlink from @u");
    truth_key(ring, "session(unlinked from @u)");
    truth_key(k, "detached-ring"); truth_read(k, "user");
    truth_rings();
    truth_read(ring, "ring");
    truth_read((int)kctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 0, 0, 0), "ring");
    idle();
    return 0;
}

static void *carol_pending(void *arg)
{
    (void)arg;
    block_usr1();
    /* Blocks until the helper instantiates the key, which it never does. */
    long id = syscall(SYS_request_key, "user", "carol:pending", "callout-pending", KEY_SPEC_SESSION_KEYRING);
    printf("TRUTH carol pending returned %ld\n", id);
    return NULL;
}

static int mode_carol(void)
{
    int ses = (int)kctl(KEYCTL_JOIN_SESSION_KEYRING, (long)"carol-session", 0, 0, 0);
    ok(ses, "join carol-session");
    long id = syscall(SYS_request_key, "user", "carol:denied", "callout-deny", KEY_SPEC_SESSION_KEYRING);
    printf("TRUTH request %s desc=carol:denied rc=%ld error=%s\n", tag, id, id < 0 ? strerror(errno) : "none");
    pthread_t t;
    if (pthread_create(&t, NULL, carol_pending, NULL)) { fprintf(stderr, "pthread_create\n"); return 1; }
    sleep(3);
    truth_key(ses, "session");
    truth_rings();
    truth_read(ses, "ring");
    idle();
    return 0;
}

/* /sbin/request-key <op> <key> <uid> <gid> <thread> <process> <session>, run by the kernel for carol. */
static int mode_helper(int argc, char **argv)
{
    int fd = open("/dev/console", O_WRONLY);
    if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
    setvbuf(stdout, NULL, _IOLBF, 0);
    tag = "helper";
    if (argc < 8) return 1;
    int key = (int)strtol(argv[2], NULL, 10);
    ok(kctl(KEYCTL_ASSUME_AUTHORITY, key, 0, 0, 0), "assume_authority");
    char callout[256] = "";
    long n = kctl(KEYCTL_READ, KEY_SPEC_REQKEY_AUTH_KEY, (long)callout, sizeof callout - 1, 0);
    if (n >= 0 && n < (long)sizeof callout) callout[n] = 0;
    long auth = kctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_REQKEY_AUTH_KEY, 0, 0, 0);
    printf("TRUTH helper pid=%d op=%s key=%08x auth=%08lx callout=%s\n", getpid(), argv[1], key, auth, callout);
    if (!strcmp(callout, "callout-deny")) {
        ok(kctl(KEYCTL_REJECT, key, 3600, EKEYREJECTED, 0), "reject");
        printf("TRUTH helper rejected key=%08x timeout=3600\n", key);
        return 0;
    }
    tag = "helper-pending";
    truth_rings();
    idle(); /* keeps the authorisation key, so the key stays under construction */
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa = { .sa_handler = on_usr1 };
    sigaction(SIGUSR1, &sa, NULL);
    const char *base = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    if (!strcmp(base, "request-key")) return mode_helper(argc, argv);
    tag = argc > 1 ? argv[1] : "";
    if (!strcmp(tag, "alice")) return mode_alice();
    if (!strcmp(tag, "bob")) return mode_bob();
    if (!strcmp(tag, "orphan")) return mode_orphan();
    if (!strcmp(tag, "carol")) return mode_carol();
    if (!strcmp(tag, "empty")) {
        /* No keyctl call at all: looking up @s installs the user-session keyring as the session keyring. */
        printf("TRUTH proc empty pid=%d tid=%d uid=%d\n", getpid(), getpid(), getuid());
        idle();
    }
    fprintf(stderr, "usage: %s alice|bob|orphan|carol|empty\n", argv[0]);
    return 2;
}
