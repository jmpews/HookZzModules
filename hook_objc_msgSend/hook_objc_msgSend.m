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

void sprintfArg(char *fd, RegState *rs, int index, char *type_name);

zpointer log_sel_start_addr = 0;
zpointer log_sel_end_addr = 0;
zpointer log_class_start_addr = 0;
zpointer log_class_end_addr = 0;
char decollators[128] = {0};
@interface HookZz : NSObject

@end

@implementation HookZz

+ (void)load {

  const struct mach_header *header = _dyld_get_image_header(0);
  struct segment_command_64 *seg_cmd_64_text = zz_macho_get_segment_64_via_name((struct mach_header_64 *)header, (char *)"__TEXT");
  zsize slide = (zaddr)header - (zaddr)seg_cmd_64_text->vmaddr;
  struct section_64 *sect_64_1 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__objc_methname");
  log_sel_start_addr = slide + (zaddr)sect_64_1->addr;
  log_sel_end_addr = log_sel_start_addr + sect_64_1->size;

  struct section_64 *sect_64_2 = zz_macho_get_section_64_via_name((struct mach_header_64 *)header, (char *)"__objc_data");
  log_class_start_addr = slide + (zaddr)sect_64_2->addr;
  log_class_end_addr = log_class_start_addr + sect_64_2->size;


  [self hook_objc_msgSend];
}

void objc_msgSend_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    char *sel_name = (char *)rs->general.regs.x1;
    // No More Work Here!!! it will be slow.
    if(sel_name > log_sel_start_addr && sel_name < log_sel_end_addr) {
        // bad code! correct-ref: https://github.com/DavidGoldman/InspectiveC/blob/299cef1c40e8a165c697f97bcd317c5cfa55c4ba/logging.mm#L27
        void *class_addr = object_getClass((void *)rs->general.regs.x0);
        void *super_class_addr = class_getSuperclass(class_addr);
        // KVO 2333
        if((class_addr > log_class_start_addr && class_addr < log_class_end_addr) || (super_class_addr > log_class_start_addr && super_class_addr < log_class_end_addr)) {
            memset(decollators, 45, 128);
            decollators[threadstack->size * 3] = '\0';
            char *class_name = ((const char *(*)(void *))object_getClassName)(class_addr);
            unsigned int class_name_length = strlen(class_name);
            
            // check View
            // if(class_name_length >= 4 && !strcmp((class_name + class_name_length - 4), "View")) {
            //     NSLog(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name);
            // }

            // check ViewController
            if(class_name_length >= 14 && !strcmp((class_name + class_name_length - 14), "ViewController")) {
                #if 1
                NSLog(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name);
                #else
                Method method = class_getInstanceMethod(class_addr, sel_name);
                int num_args = method_getNumberOfArguments(method);
                char method_name[128] = {0};
                char sel_name_tmp[128] = {0};
                char *x;
                char *y;
                x = sel_name_tmp;
                strcpy(sel_name_tmp, sel_name);
                if(!strchr(x, ':')) {
                    NSLog(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name_tmp);
                    return;

                }
                for (int i=2; strchr(x, ':') && i < num_args; i++) {
                    y = strchr(x, ':');
                    *y = '\0';
                    char *type_name = method_copyArgumentType(method, i);
                    sprintf(method_name + strlen(method_name), "%s:", x);
                    sprintfArg(method_name + strlen(method_name), rs, i, type_name);
                    x = y + 1;
                }
                NSLog(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, method_name);
                #endif
            }
        }
    }
}

void ojbc_msgSend_post_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
}

+ (void)hook_objc_msgSend {
    ZzBuildHook((void *)objc_msgSend, NULL, NULL, objc_msgSend_pre_call, ojbc_msgSend_post_call);
    ZzEnableHook((void *)objc_msgSend);
}
@end

void sprintfArg(char *fd, RegState *rs, int index, char *type_name) {
    if(index > 8) {
        sprintf(fd, "%s", "unknown");
        return;
    }

    switch(*type_name) {
        case '#':
        case '@': {
            sprintf(fd, "<class:%s>", object_getClassName(rs->general.x[index]));
        } break;
        case '*': {
            sprintf(fd, "<char *:%s>", (char *)(rs->general.x[index]));
        } break;
        case 'B':
        case 'c':
        case 'C':
        case 's':
        case 'S':
        case 'i':
        case 'I':
        case 'l':
        case 'L': {
            sprintf(fd, "<num:%ld>", rs->general.x[index]);
        } break;
        default: {
            sprintf(fd, "<%s>", "unknown");
        };
    }
}
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
