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
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

struct section_64 *zz_macho_get_section_64_via_name(struct mach_header_64 *header, char *sect_name);
zpointer zz_macho_get_section_64_address_via_name(struct mach_header_64 *header, char *sect_name);
struct segment_command_64 *zz_macho_get_segment_64_via_name(struct mach_header_64 *header, char *segment_name);

zpointer log_start_addr = 0;
zpointer log_end_addr = 0;
char decollators[128] = {0};
@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {

  const struct mach_header *header = _dyld_get_image_header(0);
  struct segment_command_64 *seg_cmd_64_text = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
  zsize slide = (zaddr)header - (zaddr)seg_cmd_64_text->vmaddr;

  struct section_64 *sect_64 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__objc_methname");
    
  log_start_addr = slide + (zaddr)sect_64->addr;
  log_end_addr = log_start_addr + sect_64->size;

  [self hook_objc_msgSend];
}

void objc_msgSend_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    char *sel_name = (char *)rs->general.regs.x1;
    if(sel_name > log_start_addr && sel_name < log_end_addr) {
        memset(decollators, 45, 128);
        decollators[threadstack->size * 3] = '\0';
        void *class_addr = (void *)rs->general.regs.x0;
        char *class_name = object_getClassName(class_addr);
        NSLog(@"thread-id: %ld| %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name);
    }
}

void ojbc_msgSend_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
}

+ (void)hook_objc_msgSend {
    ZzBuildHook((void *)objc_msgSend, NULL, NULL, objc_msgSend_pre_call, ojbc_msgSend_post_call);
    ZzEnableHook((void *)objc_msgSend);
}
@end


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
