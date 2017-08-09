
[Copy From My Blog](http://jmpews.github.io/2017/08/09/darwin/%E5%8F%8D%E8%B0%83%E8%AF%95%E5%8F%8A%E7%BB%95%E8%BF%87/)

**[AntiDebugBypass on github](https://github.com/jmpews/HookZzModules/tree/master/AntiDebugBypass)**

**代码依赖于 [HookZz](https://github.com/jmpews/HookZz), [MachoParser](https://github.com/jmpews/MachoParser)**

## 前言

对于应用安全甲方一般会在这三个方面做防御. 

按逻辑分类的话应该应该分为这三类, 但如果从实现原理的话, 应该分为两类, `用API实现的` 和 `不用API实现的`(这说的不用 API 实现, 不是指换成 inine 函数就行) . 首先使用 API 实现基本统统沦陷. 直接通过指令实现的机制还有一丝存活的可能.

本文所有相关仅仅针对 aarch64.

假设读者对下知识有了解

0. arm64 相关知识
1. macho 文件结构以及加载相关知识
2. dyld 链接 dylib 相关函数等知识

如何 hook 不定参数函数? 

技巧在于伪造原栈的副本. 具体参考下文.

通常来说必备手册

```
// 指令格式等细节
ARM Architecture Reference Manual(ARMv8, for ARMv8-A architecture profile)
https://static.docs.arm.com/ddi0487/b/DDI0487B_a_armv8_arm.pdf

ARM Cortex -A Series Programmer’s Guide for ARMv8-A
http://infocenter.arm.com/help/topic/com.arm.doc.den0024a/DEN0024A_v8_architecture_PG.pdf

Calling conventions for different C++ compilers and operating systems
http://www.agner.org/optimize/calling_conventions.pdf

Procedure Call Standard for the ARM 64-bit Architecture (AArch64)
http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf
```

通常来说必备源码

```
// dyld
https://opensource.apple.com/tarballs/dyld/

// xnu
https://opensource.apple.com/tarballs/xnu/

// objc
https://opensource.apple.com/tarballs/objc4/
https://github.com/RetVal/objc-runtime (可编译)
```

## 反调试

反调试从逻辑上分大概分为, 一种是直接屏蔽调试器挂载, 另一种就是根据特征手动检测调试器挂载. 当然也分为使用函数实现 和 直接使用内联 asm 实现.

#### ptrace 反调试

ptrace 反调试可以使用四种方法实现.

**1. 直接使用 ptrace 函数**

```
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif
typedef int (*PTRACE_T)(int request, pid_t pid, caddr_t addr, int data);

// ------------------------------------------------------------------

static void AntiDebug_ptrace() {
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    PTRACE_T ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
}
```

**2. 使用 syscall 实现**

```
#include <sys/syscall.h>
#if !defined(SYS_ptrace)
#define SYS_ptrace 26
#endif
void AntiDebug_syscall() { syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0); }
```


**3. 内联 svc + ptrace 实现**

其实这种方法等同于直接使用 ptrace, 此时系统调用号是 `SYS_ptrace`

```
static __attribute__((always_inline)) void AntiDebug_svc() {
#ifdef __arm64__
    __asm__(
        "mov X0, #31\n"
        "mov X1, #0\n"
        "mov X2, #0\n"
        "mov X3, #0\n"
        "mov w16, #26\n"
        "svc #0x80");
#endif
    return;
}
```

**4. 内联 svc + syscall + ptrace 实现**

其实这种方法等同于使用 `syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0)`, 这里需要注意, 此时的系统调用号是 0, 也就是 `SYS_syscall`

```
static __attribute__((always_inline)) void AntiDebug_svc_syscall_syscall() {
#ifdef __arm64__
    __asm__(
        "mov X0, #26\n"
        "mov X1, #31\n"
        "mov X2, #0\n"
        "mov X3, #0\n"
        "mov X4, #0\n"
        "mov w16, #0\n"
        "svc #0x80");
#endif
    return;
}
```

简单整理下系统调用流程, 只能以 `xnu-3789.41.3` 源码举例.

Supervisor Call causes a Supervisor Call exception. svc 切换 `Exception Levels ` 从 `EL0(Unprivileged)` 到 `EL1(Privileged)`

![C06F60DB066D85C69DC318113539A69C.jpg](/images/C06F60DB066D85C69DC318113539A69C.jpg)

上面说的是指令层相关, 再说系统层相关, 使用 svc 进行系统中断调用需要明确 3 个点: 中断号, 系统调用号, 以及参数. 下面以 x86-64 举例.

中断向量表

```
// xnu-3789.41.3/osfmk/x86_64/idt_table.h
USER_TRAP_SPC(0x80,idt64_unix_scall)
USER_TRAP_SPC(0x81,idt64_mach_scall)
USER_TRAP_SPC(0x82,idt64_mdep_scall)
```

中断处理函数

```
// xnu-3789.41.3/osfmk/x86_64/idt64.s
/*
 * System call handlers.
 * These are entered via a syscall interrupt. The system call number in %rax
 * is saved to the error code slot in the stack frame. We then branch to the
 * common state saving code.
 */
    
#ifndef UNIX_INT
#error NO UNIX INT!!!
#endif
Entry(idt64_unix_scall)
  swapgs        /* switch to kernel gs (cpu_data) */
  pushq %rax      /* save system call number */
  PUSH_FUNCTION(HNDL_UNIX_SCALL)
  pushq $(UNIX_INT)
  jmp L_32bit_entry_check
```

```
// xnu-3789.41.3/bsd/dev/i386/systemcalls.c
__attribute__((noreturn))
void
unix_syscall64(x86_saved_state_t *state)
{
  thread_t  thread;
  void      *vt;
  unsigned int  code;
  struct sysent *callp;
  int   args_in_regs;
  boolean_t args_start_at_rdi;
  int   error;
  struct proc *p;
  struct uthread  *uthread;
  x86_saved_state64_t *regs;
  pid_t   pid;

  assert(is_saved_state64(state));
  regs = saved_state64(state);
#if DEBUG
  if (regs->rax == 0x2000800)
    thread_exception_return();
#endif
  thread = current_thread();
  uthread = get_bsdthread_info(thread);

#if PROC_REF_DEBUG
  uthread_reset_proc_refcount(uthread);
#endif

  /* Get the approriate proc; may be different from task's for vfork() */
  if (__probable(!(uthread->uu_flag & UT_VFORK)))
    p = (struct proc *)get_bsdtask_info(current_task());
  else 
    p = current_proc();

  /* Verify that we are not being called from a task without a proc */
  if (__improbable(p == NULL)) {
    regs->rax = EPERM;
    regs->isf.rflags |= EFL_CF;
    task_terminate_internal(current_task());
    thread_exception_return();
    /* NOTREACHED */
  }

  code = regs->rax & SYSCALL_NUMBER_MASK;
  DEBUG_KPRINT_SYSCALL_UNIX(
    "unix_syscall64: code=%d(%s) rip=%llx\n",
    code, syscallnames[code >= nsysent ? SYS_invalid : code], regs->isf.rip);
  callp = (code >= nsysent) ? &sysent[SYS_invalid] : &sysent[code];

```

系统调用表

```
xnu-3789.41.3/bsd/kern/syscall.h
#define SYS_setuid         23
#define SYS_getuid         24
#define SYS_geteuid        25
#define SYS_ptrace         26
#define SYS_recvmsg        27
#define SYS_sendmsg        28
```

## 反调试检测

这里主要是调试器的检测手段, 很多检测到调试器后使用 `exit(-1)` 退出程序. 这里很容易让 cracker 断点到 `exit` 函数上. 其实有一个 trick 就是利用利用系统异常造成 crash. 比如: 操作无效内存地址. 或者覆盖/重写 `__TEXT` 内容(debugmode 模式下可以对 `rx-` 内存进行操作)

#### 使用 sysctl 检测

```
#include <sys/sysctl.h>
#include <unistd.h>
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

  if ((ret = (sysctl(name, 4, &info, &size, NULL, 0)))) {
    return ret; // sysctl() failed for some reason
  }
  return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

void AntiDebug_sysctl() {
  if (DetectDebug_sysctl()) {
    exit(1);
  }
}
```

#### 使用 isatty 检测

```

#include <unistd.h>
void AntiDebug_isatty() {
  if (isatty(1)) {
    exit(1);
  } else {
  }
}
```

#### 使用 ioctl 检测

```
#include <sys/ioctl.h>
void AntiDebug_ioctl() {
  if (!ioctl(1, TIOCGWINSZ)) {
    exit(1);
  } else {
  }
}
```

## 绕过

对于使用函数进行反调试可以使用 hook 轻松绕过, 具体的实现, 直接看代码.

#### syscall 反调试绕过

因为 `syscall` 反调试有些特殊, 这里需要介绍下如何绕过 `syscall` 反调试, 使用的是 `va_list` 进行传递参数. `http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf` 参考阅读 `va_list` 相关.

借助 [HookZz](https://github.com/jmpews/HookZz) 有两种方法可以进行绕过

**1. 使用 `replace_call` 绕过**

这里的 `syscall` 使用的是 `va_list` 传递参数. 所以这里问题在于如何 hook 不定参数函数. 因为在 hook 之后不确定原函数的参数个数. 所以没有办法调用原函数.

所以这里有一个 trick, 在 `orig_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7]);` 时伪造了一个栈, 这个栈的内容和原栈相同(应该是大于等于原栈的参数内容). 虽然传递了很多参数, 如果理解 `function call` 的原理的话, 即使传递了很多参数, 但是只要栈的内容不变, 准确的说的是从低地址到高地址的栈里的内容不变(这里可能多压了很多无用的内容到栈里), 函数调用就不会变.

这里不要使用 `large structure`, gcc 会使用 `memcopy` 最终传入的其实是地址. 大部分注释请参考下文.

```
// ptrace(int request, pid_t pid, caddr_t addr, int data);
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

  // must understand the principle of `function call`. `parameter pass` is before `switch to target`
  // so, pass the whole `stack`, it just actually faked an original stack.
  // Not pass a large structure,  will be replace with a `hidden memcpy`.
  int x = orig_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7]);
  return x;
}

__attribute__((constructor)) void patch_ptrace_sysctl_syscall() {

  ...

  zpointer syscall_ptr = (void *)syscall;
  ZZBuildHook((void *)syscall_ptr, (void *)fake_syscall, (void
  **)&orig_syscall,
              NULL, NULL);
  ZZEnableHook((void *)syscall_ptr);
}
// --- end --
```

**2. 使用 `pre_call` 绕过**

这种方法需要查看 `syscall` 的汇编实现, 来确定 `PT_DENY_ATTACH` 放在哪一个寄存器.

```
libsystem_kernel.dylib`__syscall:
    0x1815c0900 <+0>:  ldp    x1, x2, [sp]
    0x1815c0904 <+4>:  ldp    x3, x4, [sp, #0x10]
    0x1815c0908 <+8>:  ldp    x5, x6, [sp, #0x20]
    0x1815c090c <+12>: ldr    x7, [sp, #0x30]
    0x1815c0910 <+16>: mov    x16, #0x0
    0x1815c0914 <+20>: svc    #0x80
    0x1815c0918 <+24>: b.lo   0x1815c0930               ; <+48>
    0x1815c091c <+28>: stp    x29, x30, [sp, #-0x10]!
    0x1815c0920 <+32>: mov    x29, sp
    0x1815c0924 <+36>: bl     0x1815a6dc0               ; cerror
    0x1815c0928 <+40>: mov    sp, x29
    0x1815c092c <+44>: ldp    x29, x30, [sp], #0x10
    0x1815c0930 <+48>: ret  
```

可以看到调用如果 `x0` 是 `SYS_ptrace`, 那么 `PT_DENY_ATTACH` 存放在 `[sp]`.

```
// --- syscall bypass use `pre_call`
void syscall_pre_call(struct RegState_ *rs) {
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
  ZZBuildHook((void *)syscall_ptr, NULL, NULL, (void *)syscall_pre_call, NULL);
  ZZEnableHook((void *)syscall_ptr);
}

// --- end ---
```

这里介绍关键是介绍如何对 svc 反调试的绕过.

上面已经对 svc 进行了简单的介绍. 所以理所当然想到的是希望通过 `syscall hook`, 劫持 `system call table(sysent)` . 这里相当于实现 `syscall hook`. 但是难点之一是需要找到 `system call table(sysent)`, 这一步可以通过 [joker](http://newosxbook.com/tools/joker.html), 对于 IOS 10.x 可以参考 `http://ioshackerwiki.com/syscalls/`, 难点之二是作为 kext 加载. 可以参考 **附录**.

ok, 接下来使用另一种思路对绕过, 其实也就是 `code patch` + `inlinehook`. 对 `__TEXT` 扫描 `svc #0x80` 指令, 对于 cracker 来说, 在 `__TEXT` 段使用 `svc #0x80` 具有一定的反调试可能, 所以需要对 `svc #0x80` 进行 `inlinehook`, 这里并不直接对 `svc $0x80` 进行覆盖操作, 可能有正常系统调用.

以下代码依赖于 [HookZz](https://github.com/jmpews/HookZz), [MachoParser](https://github.com/jmpews/MachoParser)

大致原理就是先搜索到 `svc #0x80` 指令后, 对该指令地址进行 hook, 之后使用 `pre_call` 修改寄存器的值.

```
// --- svc #0x80 bypass ---

#include "MachoMem.h"
void patch_svc_pre_call(struct RegState_ *rs) {
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
      *(unsigned long *)(&rs->general.regs.x1) = 10;
      NSLog(@"[AntiDebugBypass] catch 'SVC-0x80; ptrace' and bypass");
    }
  }
}
__attribute__((constructor)) void patch_svc_x80() {
  const section_64_info_t *sect64;
  zaddr svc_x80_addr;
  zaddr curr_addr, end_addr;
  uint32_t svc_x80_byte = 0xd4001001;
  MachoMem *mem = new MachoMem();
  mem->parse_macho();
  // mem->parse_dyld();
  sect64 = mem->get_sect_by_name("__text");
  curr_addr = sect64->sect_addr;
  end_addr = curr_addr + sect64->sect_64->size;

  ZZInitialize();
  while (curr_addr < end_addr) {
    svc_x80_addr = mem->macho_search_data(
        sect64->sect_addr, sect64->sect_addr + sect64->sect_64->size,
        (const zbyte *)&svc_x80_byte, 4);
    if (svc_x80_addr) {
      NSLog(@"find svc #0x80 at %p with aslr (%p without aslr)",
            (void *)svc_x80_addr, (void *)(svc_x80_addr - mem->m_aslr_slide));
      ZZBuildHook((void *)svc_x80_addr, NULL, NULL,
                  (zpointer)patch_svc_pre_call, NULL);
      ZZEnableHook((void *)svc_x80_addr);
      curr_addr = svc_x80_addr + 4;
    } else {
      break;
    }
  }
}
// --- end ---
```

## 总结

上文对很多的反调试原理做了总结, 也有一些没有讲到原理. 读者可以自行研究.

## 附录

```
// syscall hook
http://siliconblade.blogspot.jp/2013/07/offensive-volatility-messing-with-os-x.html
https://www.defcon.org/images/defcon-17/dc-17-presentations/defcon-17-bosse_eriksson-kernel_patching_on_osx.pdf
http://d.hatena.ne.jp/hon53/20100926/1285476759
https://papers.put.as/papers/ios/2011/SysScan-Singapore-Targeting_The_IOS_Kernel.pdf
```