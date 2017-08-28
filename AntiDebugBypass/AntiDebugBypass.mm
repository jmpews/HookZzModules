extern "C" {
#include "hookzz.h"
}

#import <Foundation/Foundation.h>

#include <sys/sysctl.h>

#include <mach-o/dyld.h>

struct section_64 *zz_macho_get_section_64_via_name(struct mach_header_64 *header, char *sect_name);
zpointer zz_macho_get_section_64_address_via_name(struct mach_header_64 *header, char *sect_name);
zpointer zz_vm_search_data(const zpointer start_addr, zpointer end_addr, zbyte *data, zsize data_len);
struct segment_command_64 *zz_macho_get_segment_64_via_name(struct mach_header_64 *header, char *segment_name);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
#if !defined(SYS_syscall)
#define SYS_syscall 0
#endif
#if !defined(SYS_sysctl)
#define SYS_sysctl 202
#endif


// ============= ptrace, sysctl, syscall bypass =============

// runtime to get symbol address, but must link with `
// -Wl,-undefined,dynamic_lookup` or you can use `dlopen` and `dlsym`
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int fake_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        NSLog(@"[AntiDebugBypass] catch 'ptrace(PT_DENY_ATTACH)' and bypass.");
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                   void *newp, size_t newlen);
int fake_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                void *newp, size_t newlen) {
    struct kinfo_proc *info = NULL;
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        info = (struct kinfo_proc *)oldp;
        info->kp_proc.p_flag &= ~(P_TRACED);
        NSLog(@"[AntiDebugBypass] catch 'sysctl' and bypass.");
    }
    return ret;
}

int (*orig_syscall)(int number, ...);
int fake_syscall(int number, ...) {
    int request;
    pid_t pid;
    caddr_t addr;
    int data;
    
    // fake stack, why use `char *` ? hah
    char *stack[8];
    
    va_list args;
    va_start(args, number);
    
    // get the origin stack args copy.(must >= origin stack args)
    memcpy(stack, args, 8 * 8);
    
    if (number == SYS_ptrace) {
        request = va_arg(args, int);
        pid = va_arg(args, pid_t);
        addr = va_arg(args, caddr_t);
        data = va_arg(args, int);
        va_end(args);
        if (request == PT_DENY_ATTACH) {
            NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
                  @"0, 0)' and bypass.");
            return 0;
        }
    } else {
        va_end(args);
    }
    
    // must understand the principle of `function call`. `parameter pass` is
    // before `switch to target` so, pass the whole `stack`, it just actually
    // faked an original stack. Do not pass a large structure,  will be replace with
    // a `hidden memcpy`.
    int x = orig_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4],
                         stack[5], stack[6], stack[7]);
    return x;
}

__attribute__((constructor)) void patch_ptrace_sysctl_syscall() {
    
    zpointer ptrace_ptr = (void *)ptrace;
    ZzBuildHook((void *)ptrace_ptr, (void *)fake_ptrace, (void **)&orig_ptrace,
                NULL, NULL);
    ZzEnableHook((void *)ptrace_ptr);
    
    zpointer sysctl_ptr = (void *)sysctl;
    ZzBuildHook((void *)sysctl_ptr, (void *)fake_sysctl, (void **)&orig_sysctl,
                NULL, NULL);
    ZzEnableHook((void *)sysctl_ptr);
    
    zpointer syscall_ptr = (void *)syscall;
    ZzBuildHook((void *)syscall_ptr, (void *)fake_syscall, (void **)&orig_syscall,
                NULL, NULL);
    ZzEnableHook((void *)syscall_ptr);
}
// ============= end =============


// ============= syscall bypass with `pre_call` =============
void syscall_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    int num_syscall;
    int request;
    zpointer sp;
    num_syscall = (int)(uint64_t)(rs->general.regs.x0);
    if (num_syscall == SYS_ptrace) {
        sp = (zpointer)(rs->sp);
        request = *(int *)sp;
        if (request == PT_DENY_ATTACH) {
            *(long *)sp = 10;
            NSLog(@"[AntiDebugBypass] catch 'syscall(SYS_ptrace, PT_DENY_ATTACH, 0, "
                  @"0, 0)' and bypass.");
        }
    }
}
__attribute__((constructor)) void patch_syscall_by_pre_call() {
    zpointer syscall_ptr = (void *)syscall;
    #if 0
    ZzBuildHook((void *)syscall_ptr, NULL, NULL, syscall_pre_call, NULL);
    ZzEnableHook((void *)syscall_ptr);
    #endif
}
// ============= end =============


// ============= svc #0x80 bypass with `pre_call` & `post_call` =============

void hook_svc_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    int num_syscall;
    int request;
    num_syscall = (int)(uint64_t)(rs->general.regs.x16);
    request = (int)(uint64_t)(rs->general.regs.x0);
    
    if (num_syscall == SYS_syscall) {
        int arg1 = (int)(uint64_t)(rs->general.regs.x1);
        if (request == SYS_ptrace && arg1 == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x1) = 10;
            NSLog(@"[AntiDebugBypass] catch 'SVC #0x80; syscall(ptrace)' and bypass");
        }
        
    } else if (num_syscall == SYS_ptrace) {
        request = (int)(uint64_t)(rs->general.regs.x0);
        if (request == PT_DENY_ATTACH) {
            *(unsigned long *)(&rs->general.regs.x0) = 10;
            NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; ptrace' and bypass");
        }
    } else if(num_syscall == SYS_sysctl) {
        STACK_SET(callstack, (char *)"num_syscall", num_syscall, int);
        STACK_SET(callstack, (char *)"info_ptr", rs->general.regs.x2, zpointer);
    }
}

void hook_svc_half_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    // emmm... little long...
    if(STACK_CHECK_KEY(callstack, (char *)"num_syscall")) {
        int num_syscall = STACK_GET(callstack, (char *)"num_syscall", int);
        struct kinfo_proc *info = STACK_GET(callstack, (char *)"info_ptr", struct kinfo_proc *);
        if (num_syscall == SYS_sysctl)
        {
            NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; sysctl' and bypass");
            info->kp_proc.p_flag &= ~(P_TRACED);
        }
    }
}

/* Two choice */

/* 1. use MachoParser */

#if 0
#include "MachoMem.h"
__attribute__((constructor)) void hook_svc_x80() {
  const section_64_info_t *sect64;
  zaddr svc_x80_addr;
  zaddr curr_addr, end_addr;
  uint32_t svc_x80_byte = 0xd4001001;
  MachoMem *mem = new MachoMem();
  mem->parse_macho();
  sect64 = mem->get_sect_by_name("__text");
  curr_addr = sect64->sect_addr;
  end_addr = curr_addr + sect64->sect_64->size;

  ZzInitialize();
  while (curr_addr < end_addr) {
    svc_x80_addr = mem->macho_search_data(curr_addr, sect64->sect_addr + sect64->sect_64->size, (const zbyte *)&svc_x80_byte, 4);
    if (svc_x80_addr) {
      NSLog(@"hook svc #0x80 at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr - mem->m_aslr_slide));
      ZzBuildHookAddress((void *)svc_x80_addr, (void *)(svc_x80_addr + 4),
                         hook_svc_pre_call, hook_svc_half_call);
      ZzEnableHook((void *)svc_x80_addr);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
#endif

/* 2. use zzdeps */

__attribute__((constructor)) void hook_svc_x80() {
    zaddr svc_x80_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    
    const struct mach_header *header = _dyld_get_image_header(0);
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;
    
    while (curr_addr < text_end_addr) {
        svc_x80_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x80_byte, 4);
        if (svc_x80_addr) {
            NSLog(@"hook svc #0x80 at %p with aslr (%p without aslr)",
                  (void *)svc_x80_addr, (void *)(svc_x80_addr - slide));
            ZzBuildHookAddress((void *)svc_x80_addr, (void *)(svc_x80_addr + 4),
                               hook_svc_pre_call, hook_svc_half_call);
            ZzEnableHook((void *)svc_x80_addr);
            curr_addr = svc_x80_addr + 4;
        } else {
            break;
        }
    }
}

// ============= end =============


// ============= svc #0x80 bypass with `RuntimeCodePatch` =============
#if 0
__attribute__((constructor)) void patch_svc_x80_with_nop() {
    zaddr svc_x80_addr;
    zaddr curr_addr, text_start_addr, text_end_addr;
    uint32_t svc_x80_byte = 0xd4001001;
    
    const struct mach_header *header = _dyld_get_image_header(0);
    struct segment_command_64 *seg_cmd_64 = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
    zsize slide = (zaddr)header - (zaddr)seg_cmd_64->vmaddr;
    
    struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__text");
    
    text_start_addr = slide + (zaddr)sect_64->addr;
    text_end_addr = text_start_addr + sect_64->size;
    curr_addr = text_start_addr;

    while (curr_addr < text_end_addr) {
        svc_x80_addr = (zaddr)zz_vm_search_data((zpointer)curr_addr, (zpointer)text_end_addr, (zbyte *)&svc_x80_byte, 4);
        if (svc_x80_addr) {
      NSLog(@"patch svc #0x80 with 'nop' at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr -
            slide));
      unsigned long nop_bytes = 0xD503201F;
      ZzRuntimeCodePatch(svc_x80_addr, (zpointer)&nop_bytes, 4);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
#endif
// ============= end =============


// ============= [zzdeps](https://github.com/jmpews/zzdeps) =============
struct section_64 *
zz_macho_get_section_64_via_name(struct mach_header_64 *header,
                                 char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    
    load_cmd = (struct load_command *)((zaddr)header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((zaddr)load_cmd + load_cmd->cmdsize)) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            sect_64 = (struct section_64 *)((zaddr)seg_cmd_64 +
                                            sizeof(struct segment_command_64));
            for (zsize j = 0; j < seg_cmd_64->nsects;
                 j++, sect_64 = (struct section_64 *)((zaddr)sect_64 + sizeof(struct section_64))) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return sect_64;
                }
            }
        }
    }
    return NULL;
}

zpointer zz_macho_get_section_64_address_via_name(struct mach_header_64 *header,
                                                  char *sect_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    zsize slide, linkEditBase;
    
    load_cmd = (struct load_command *)((zaddr)header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((zaddr)load_cmd + load_cmd->cmdsize)) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if ( (seg_cmd_64->fileoff == 0) && (seg_cmd_64->filesize != 0) ) {
                slide = (uintptr_t)header - seg_cmd_64->vmaddr;
            }
            if ( strcmp(seg_cmd_64->segname, "__LINKEDIT") == 0 ) {
                linkEditBase = seg_cmd_64->vmaddr - seg_cmd_64->fileoff + slide;
            }
            sect_64 = (struct section_64 *)((zaddr)seg_cmd_64 +
                                            sizeof(struct segment_command_64));
            for (zsize j = 0; j < seg_cmd_64->nsects;
                 j++, sect_64 = (struct section_64 *)((zaddr)sect_64 + sizeof(struct section_64))) {
                if (!strcmp(sect_64->sectname, sect_name)) {
                    return (zpointer)(sect_64->addr + slide);
                }
            }
        }
    }
    return NULL;
}


zpointer zz_vm_search_data(const zpointer start_addr, zpointer end_addr, zbyte *data,
                           zsize data_len)
{
    zpointer curr_addr;
    if (start_addr <= 0)
        printf("search address start_addr(%p) < 0", (zpointer)start_addr);
    if (start_addr > end_addr)
        printf("search start_add(%p) < end_addr(%p)", (zpointer)start_addr, (zpointer)end_addr);
    
    curr_addr = start_addr;
    
    while (end_addr > curr_addr)
    {
        if (!memcmp(curr_addr, data, data_len))
        {
            return curr_addr;
        }
        curr_addr = (zpointer)((zaddr)curr_addr + data_len);
    }
    return 0;
}

struct segment_command_64 *
zz_macho_get_segment_64_via_name(struct mach_header_64 *header,
                                 char *segment_name) {
    struct load_command *load_cmd;
    struct segment_command_64 *seg_cmd_64;
    struct section_64 *sect_64;
    
    load_cmd = (struct load_command *)((zaddr)header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((zaddr)load_cmd + load_cmd->cmdsize)) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            seg_cmd_64 = (struct segment_command_64 *)load_cmd;
            if(!strcmp(seg_cmd_64->segname, segment_name)) {
                return seg_cmd_64;
            }
        }
    }
    return NULL;
}
// ============= end =============