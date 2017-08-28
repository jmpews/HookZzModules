/**
 *    Copyright 2017 jmpews
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "hookzz.h"
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {
  [self hookMGCopyAnswer];
}

NSString *RequestMG(NSString *req) {
    static NSString *response = nil;

    void *lib = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    CFStringRef (*MGCopyAnswer_ptr)(CFStringRef property) = dlsym(lib, "MGCopyAnswer");
    
    response = (__bridge NSString*)MGCopyAnswer_ptr((__bridge CFStringRef)req);
    if (!response) {
        response = @"unknown";
    }
    
    return response;
}
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

+ (void)hookMGCopyAnswer {
    void *lib = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    void *MGCopyAnswer_addr = dlsym(lib, "MGCopyAnswer");
    ZzBuildHook((void *)MGCopyAnswer_addr, new_MGCopyAnswer, &orig_MGCopyAnswer, MGCopyAnswer_pre_call, MGCopyAnswer_post_call);
    ZzEnableHook((void *)MGCopyAnswer_addr);

    NSLog(@"MGResponse: %@", RequestMG(@"CPUArchitecture"));
}
@end
