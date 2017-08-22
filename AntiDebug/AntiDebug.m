#include "AntiDebug.h"
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
#if !defined(SYS_syscall)
#define SYS_syscall 0
#endif

static __attribute__((always_inline)) void asm_exit() {
#ifdef __arm64__
    __asm__("mov X0, #0\n"
            "mov w16, #1\n"
            "svc #0x80\n"
            "mov x1, #0\n"
            "mov sp, x1\n"
            "mov x29, x1\n"
            "mov x30, x1\n"
            "ret");
#endif
}

static __attribute__((always_inline)) void check_svc_integrity() {
    int pid;
    static jmp_buf protectionJMP;
#ifdef __arm64__
    __asm__("mov x0, #0\n"
            "mov w16, #20\n"
            "svc #0x80\n"
            "cmp x0, #0\n"
            "b.ne #24\n"
            
            "mov x1, #0\n"
            "mov sp, x1\n"
            "mov x29, x1\n"
            "mov x30, x1\n"
            "ret\n"
            
            "mov %[result], x0\n"
            : [result] "=r" (pid)
            :
            :
            );
    
    if(pid == 0) {
        longjmp(protectionJMP, 1);
    }
#endif
}

// ------------------------------------------------------------------

typedef int (*PTRACE_T)(int request, pid_t pid, caddr_t addr, int data);
static void AntiDebug_001() {
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    PTRACE_T ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
}

// ------------------------------------------------------------------

// runtime to get symbol address, but must link with `
// -Wl,-undefined,dynamic_lookup` or you can use `dlopen` and `dlsym`
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
static void AntiDebug_002() { ptrace(PT_DENY_ATTACH, 0, 0, 0); }

// ------------------------------------------------------------------

static __attribute__((always_inline)) void AntiDebug_003() {
#ifdef __arm64__
    __asm__("mov X0, #31\n"
            "mov X1, #0\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov w16, #26\n"
            "svc #0x80");
#endif
}

// ------------------------------------------------------------------

static __attribute__((always_inline)) void AntiDebug_004() {
#ifdef __arm64__
    __asm__("mov X0, #26\n"
            "mov X1, #31\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov X4, #0\n"
            "mov w16, #0\n"
            "svc #0x80");
#endif
}

// ------------------------------------------------------------------

void AntiDebug_005() { syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0); }

// ------------------------------------------------------------------

static int DetectDebug_sysctl() __attribute__((always_inline));
int DetectDebug_sysctl() {
    size_t size = sizeof(struct kinfo_proc);
    struct kinfo_proc info;
    int ret, name[4];
    
    memset(&info, 0, sizeof(struct kinfo_proc));
    
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
#if 0
    if ((ret = (sysctl(name, 4, &info, &size, NULL, 0)))) {
        return ret; // sysctl() failed for some reason
    }
#else
    // also can change as `AntiDebug_003` and `AntiDebug_004`
    // https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html
    __asm__ volatile("mov x0, %[name_ptr]\n"
                     "mov x1, #4\n"
                     "mov x2, %[info_ptr]\n"
                     "mov x3, %[size_ptr]\n"
                     "mov x4, #0\n"
                     "mov x5, #0\n"
                     "mov w16, #202\n"
                     "svc #0x80"
                     :
                     : [name_ptr] "r"(name), [info_ptr] "r"(&info),
                     [size_ptr] "r"(&size));
#endif
    
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

void AntiDebug_006() {
    if (DetectDebug_sysctl()) {
        asm_exit();
    }
}

// ------------------------------------------------------------------

#include <unistd.h>
void AntiDebug_007() {
    if (isatty(1)) {
        asm_exit();
    } else {
    }
}

// ------------------------------------------------------------------

#include <sys/ioctl.h>
void AntiDebug_008() {
    if (!ioctl(1, TIOCGWINSZ)) {
        asm_exit();
    } else {
    }
}

// ------------------------------------------------------------------

void AntiCracker() {
    check_svc_integrity();
    AntiDebug_001();
    AntiDebug_002();
    AntiDebug_003();
    AntiDebug_003();
    AntiDebug_005();
    AntiDebug_006();
    AntiDebug_007();
    AntiDebug_008();
}