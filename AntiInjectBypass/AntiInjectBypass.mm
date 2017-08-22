
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


// uint32_t _dyld_image_count(void);
// void _dyld_register_func_for_add_image(
//     void (*func)(const struct mach_header *mh, intptr_t vmaddr_slide));
// struct mach_header *_dyld_get_image_header(uint32_t image_index);
// char *_dyld_get_image_name(uint32_t image_index);

#include <mach-o/dyld.h>
#import <objc/runtime.h>
void DetectLoadDylibs() {
  // struct mach_header *_dyld_get_image_header(uint32_t image_index);
  const struct mach_header *header;
  zpointer load_cmd_addr;
  struct load_command *load_cmd;
  struct dylib_command *dy_cmd;
  struct dylib lib;
  const char *dylib_name;

  header = _dyld_get_image_header(0);

  bool is64bit = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
  if (is64bit) {
    load_cmd_addr = (zpointer)(header + sizeof(struct mach_header_64));
    for (zsize i = 0; i < header->ncmds; i++) {
      load_cmd = (struct load_command *)load_cmd_addr;
      if (load_cmd->cmd == LC_ID_DYLIB) {
        dy_cmd = (struct dylib_command *)load_cmd_addr;
        lib = dy_cmd->dylib;
        dylib_name = (char *)(load_cmd_addr + lib.name.offset);
      }
    }
  }
}

void DetectImageList() {
  zsize count = _dyld_image_count();
  const char *dyld_name;
  for (zsize i = 0; i < count; i++) {
    dyld_name = _dyld_get_image_name(i);
  }
}
void DetectFileList() {
  if ([[NSFileManager defaultManager]
          fileExistsAtPath:@"/Applications/Cydia.app"]) {
  }
}