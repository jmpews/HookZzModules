# hook_MGCopyAnswer

**You need to specify the `Hookz` path, and the build dylib's `-install_name` in `makefile`.**


before hookzz.

```
(lldb) disass -s 0x0000000183114294
libMobileGestalt.dylib`MGCopyAnswer:
    0x183114294 <+0>:  mov    x1, #0x0
    0x183114298 <+4>:  b      0x18311429c               ; ___lldb_unnamed_symbol64$$libMobileGestalt.dylib

libMobileGestalt.dylib`___lldb_unnamed_symbol64$$libMobileGestalt.dylib:
    0x18311429c <+0>:  stp    x24, x23, [sp, #-0x40]!
    0x1831142a0 <+4>:  stp    x22, x21, [sp, #0x10]
    0x1831142a4 <+8>:  stp    x20, x19, [sp, #0x20]
    0x1831142a8 <+12>: stp    x29, x30, [sp, #0x30]
    0x1831142ac <+16>: add    x29, sp, #0x30            ; =0x30 
    0x1831142b0 <+20>: sub    sp, sp, #0x30             ; =0x30 
```

after hookzz.

```
(lldb) disass -s 0x0000000183114294
libMobileGestalt.dylib`MGCopyAnswer:
    0x183114294 <+0>:  b      0x17b114294
    0x183114298 <+4>:  b      0x18311429c               ; ___lldb_unnamed_symbol64$$libMobileGestalt.dylib

libMobileGestalt.dylib`___lldb_unnamed_symbol64$$libMobileGestalt.dylib:
    0x18311429c <+0>:  stp    x24, x23, [sp, #-0x40]!
    0x1831142a0 <+4>:  stp    x22, x21, [sp, #0x10]
    0x1831142a4 <+8>:  stp    x20, x19, [sp, #0x20]
    0x1831142a8 <+12>: stp    x29, x30, [sp, #0x30]
    0x1831142ac <+16>: add    x29, sp, #0x30            ; =0x30 
    0x1831142b0 <+20>: sub    sp, sp, #0x30             ; =0x30 
```

## 1. hack with `pre_call` & `post_call`

```c
void MGCopyAnswer_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    CFStringRef request = (CFStringRef)rs->general.regs.x0;
    STACK_SET(callstack, "request", request, CFStringRef);
    NSLog(@"request is: %@", request);
}

void MGCopyAnswer_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    if(STACK_CHECK_KEY(callstack, "request")) {
        CFStringRef request = STACK_GET(callstack, "request", CFStringRef);
        CFPropertyListRef result = (CFPropertyListRef)rs->general.regs.x0;
        if( [(__bridge NSString *) request isEqualToString:@"CPUArchitecture"] && [(__bridge NSString *) result isEqualToString:@"123456"]) {
            CFStringRef zzarch = CFSTR("654321");
            CFStringRef *tmp = (CFStringRef *)&rs->general.regs.x0;
            *tmp = zzarch;
            // rs->general.regs.x0 = (void *)zzarch;
        }
            
        NSLog(@"result is: %@", result);
    }
}
```

## 2. hack with `replace_call`

```c
static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef prop);
CFPropertyListRef new_MGCopyAnswer(CFStringRef prop) {
    CFPropertyListRef value = nil;
    NSString *answerKey = (__bridge NSString *)prop;
    if (!strcmp(CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman), "UniqueDeviceID")) {
        return @"123456";
    }
    if (!strcmp(CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman), "CPUArchitecture")) {
        return @"123456";
    }

    return orig_MGCopyAnswer(prop);
}
```

#### hook output

```
2017-08-28 20:33:31.642 T007[640:172323] request is: CPUArchitecture
2017-08-28 20:33:31.644 T007[640:172323] result is: 123456
2017-08-28 20:33:31.645 T007[640:172323] MGResponse: 654321
```