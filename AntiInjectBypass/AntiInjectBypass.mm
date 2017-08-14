
extern "C" {
#include "hookzz.h"
}

#import <Foundation/Foundation.h>

#include <mach/dyld>


@interface SpiderZz : NSObject

@end

@implementation SpiderZz

NSString *docPath;
NSString *mainPath;

+ (void)load {
  [self zzPrintDirInfo];
  [self zzMethodSwizzlingHook];
}

void objcMethod_pre_call(struct RegState_ *rs) {
  NSLog(@"hookzz OC-Method: -[ViewController %s]",
        (zpointer)(rs->general.regs.x1));
}

+ (void)zzMethodSwizzlingHook {
  Class hookClass = objc_getClass("UIViewController");
  SEL oriSEL = @selector(viewWillAppear:);
  Method oriMethod = class_getInstanceMethod(hookClass, oriSEL);
  IMP oriImp = method_getImplementation(oriMethod);

  ZZInitialize();
  ZZBuildHook((void *)oriImp, NULL, NULL, (zpointer)objcMethod_pre_call, NULL);
  ZZEnableHook((void *)oriImp);
}

+ (void)zzPrintDirInfo {
  // 获取Documents目录
  docPath = [NSSearchPathForDirectoriesInDomains(
      NSDocumentDirectory, NSUserDomainMask, YES) lastObject];

  // 获取tmp目录
  NSString *tmpPath = NSTemporaryDirectory();

  // 获取Library目录
  NSString *libPath = [NSSearchPathForDirectoriesInDomains(
      NSLibraryDirectory, NSUserDomainMask, YES) lastObject];

  // 获取Library/Caches目录
  NSString *cachePath = [NSSearchPathForDirectoriesInDomains(
      NSCachesDirectory, NSUserDomainMask, YES) lastObject];

  // 获取Library/Preferences目录
  NSString *prePath = [NSSearchPathForDirectoriesInDomains(
      NSPreferencePanesDirectory, NSUserDomainMask, YES) lastObject];

  // 获取应用程序包的路径
  mainPath = [NSBundle mainBundle].resourcePath;

  NSLog(@"docPath: %@", docPath);
  NSLog(@"tmpPath: %@", tmpPath);
  NSLog(@"libPath: %@", libPath);
  NSLog(@"mainPath: %@", mainPath);
}

+ (bool)dlopenLoadDylibWithPath:(NSString *)path {
  void *libHandle = NULL;
  libHandle =
      dlopen([path cStringUsingEncoding:NSUTF8StringEncoding], RTLD_NOW);
  if (libHandle == NULL) {
    char *error = dlerror();
    NSLog(@"dlopen error: %s", error);
  } else {
    NSLog(@"dlopen load framework success.");
  }
  return false;
}

+ (bool)zzIsFileExist:(NSString *)filePath {
  NSFileManager *manager = [NSFileManager defaultManager];
  if (![manager fileExistsAtPath:filePath]) {
    NSLog(@"There isn't have the file");
    return YES;
  }
  return FALSE;
}

@end
