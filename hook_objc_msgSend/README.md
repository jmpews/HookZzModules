## hook_objc_msgSend

**You need to specify the `Hookz` path, and the build dylib's `-install_name` in `makefile`.**

because of `objc_msgSend` call so often, must specify where log start and end.

with filter `object_getClassName(class_addr)`, you can do more Interesting job.

```
void objc_msgSend_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    char *sel_name = (char *)rs->general.regs.x1;
    if(sel_name > log_start_addr && sel_name < log_end_addr) {
        memset(decollators, 45, 128);
        decollators[threadstack->size * 3] = '\0';
        void *class_addr = (void *)rs->general.regs.x0;
        char *class_name = object_getClassName(class_addr);
        NSLog(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name);
    }
}
```

#### inject to `Wechat`.

```
2017-08-28 21:15:50.563 WeChat[683:180872] thread-id: 6993719296 | --- [WSConfigUtil configPath]
2017-08-28 21:15:50.563 WeChat[683:180872] thread-id: 6993719296 | ------ [FTSUtil getUserFTSRootDir]
2017-08-28 21:15:50.568 WeChat[683:180872] thread-id: 6993719296 | --------- [CUtility GetPathOfLocalUsrDir]
2017-08-28 21:15:50.571 WeChat[683:180872] thread-id: 6993719296 | ------------ [CUtility GetMd5StrOfLocalUsr]
2017-08-28 21:15:50.576 WeChat[683:180872] thread-id: 6993719296 | ------------ [CUtility GetDocPath]
2017-08-28 21:15:50.577 WeChat[683:180872] thread-id: 6993719296 | --------------- [__NSArrayI safeObjectAtIndex:]
2017-08-28 21:15:50.586 WeChat[683:180872] thread-id: 6993719296 | --- [PBCoder decodeObjectOfClass:fromFile:]
2017-08-28 21:15:50.597 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleInitWithObjectsCount:]
2017-08-28 21:15:50.597 WeChat[683:180872] thread-id: 6993719296 | ------ [NSArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.602 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleObjectAtIndex:]
2017-08-28 21:15:50.602 WeChat[683:180872] thread-id: 6993719296 | ------ [NSArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.606 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleInitWithObjectsCount:]
2017-08-28 21:15:50.607 WeChat[683:180872] thread-id: 6993719296 | ------ [NSMutableArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.611 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleAddObject:]
2017-08-28 21:15:50.611 WeChat[683:180872] thread-id: 6993719296 | ------ [NSMutableArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.615 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleInsertObjectAtIndex:]
2017-08-28 21:15:50.615 WeChat[683:180872] thread-id: 6993719296 | ------ [NSMutableArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.619 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleRemoveObjectAtIndex:]
2017-08-28 21:15:50.620 WeChat[683:180872] thread-id: 6993719296 | ------ [NSMutableArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.624 WeChat[683:180872] thread-id: 6993719296 | --- [NSArray swizzleReplaceObjectAtIndexWithObject:]
2017-08-28 21:15:50.624 WeChat[683:180872] thread-id: 6993719296 | ------ [NSMutableArray swizzleMethod:withMethod:]
2017-08-28 21:15:50.632 WeChat[683:180872] thread-id: 6993719296 | --- [UIView swizzleClassMethod:withClassMethod:]
2017-08-28 21:15:50.632 WeChat[683:180872] thread-id: 6993719296 | ------ [NSObject swizzleMethod:withMethod:]
2017-08-28 21:15:50.641 WeChat[683:180872] thread-id: 6993719296 | --- [NSCache swizzleMethod:withMethod:]
```