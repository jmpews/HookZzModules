
## 前言

逆向很多的入手情况可能需要找到, 通过 `cycript` + `Reveal` 找到当前 `View` 的 `ViewController`.

但其实我们可以通过 hook 住 `objc_msgSend` 提供一些思路, 有个问题就是 `objc_msgSend` 调用过于频繁, 不能所有都打印, 那么可以借助 [HookZz](https://github.com/jmpews/HookZz) 搞一些事情.

可能有人疑问, 这个和 `logify` 关系.

1. 打印通用 `ViewController`, 无需具体的类.
2. 显示调用层级.

## hook_objc_msgSend

具体细节可以查看代码. [Move to hook_objc_msgSend](https://github.com/jmpews/HookZzModules/tree/master/hook_objc_msgSend)

本来想解析一下参数的, 没解析完, 有兴趣的可以参考 [Move to InspectiveC](https://github.com/DavidGoldman/InspectiveC/blob/299cef1c40e8a165c697f97bcd317c5cfa55c4ba/logging.mm)

预先设置了几种 trace 方式, 有需求的同学, 可以按照需求尝试.

```
void objc_msgSend_pre_call(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    char *sel_name = (char *)rs->general.regs.x1;
    // No More Work Here!!! it will be slow.
    if(LOG_ALL_SEL || (sel_name > log_sel_start_addr && sel_name < log_sel_end_addr)) {
        // bad code! correct-ref: https://github.com/DavidGoldman/InspectiveC/blob/299cef1c40e8a165c697f97bcd317c5cfa55c4ba/logging.mm#L27
        void *class_addr = zz_macho_object_get_class((id)rs->general.regs.x0);
        if(!class_addr)
            return;
        
        void *super_class_addr = class_getSuperclass(class_addr);
        // KVO 2333
        if(LOG_ALL_CLASS || ((class_addr > log_class_start_addr && class_addr < log_class_end_addr) || (super_class_addr > log_class_start_addr && super_class_addr < log_class_end_addr))) {
            memset(decollators, 45, 128);
            if(threadstack->size * 3 >= 128)
                return;
            decollators[threadstack->size * 3] = '\0';
            char *class_name = class_getName(class_addr);
            unsigned int class_name_length = strlen(class_name);
            

            
#if 1
            // check View
            if(class_name_length >= 4 && !strcmp((class_name + class_name_length - 4), "View")) {
                printf(@"thread-id: %ld | %s [%s %s]", threadstack->thread_id, decollators, class_name, sel_name);
            }
#endif
#if 0
            printf("thread-id: %ld | %s [%s %s]\n", threadstack->thread_id, decollators, class_name, sel_name);
#endif
#if 1
            // check ViewController
            if(class_name_length >= 14 && !strcmp((class_name + class_name_length - 14), "ViewController")) {
                printf("thread-id: %ld | %s [%s %s]\n", threadstack->thread_id, decollators, class_name, sel_name);
            }
#endif
#if 0
            // check ViewController with parse parameters (ref readme.md)
            if(class_name_length >= 14 && !strcmp((class_name + class_name_length - 14), "ViewController")) {
                Method method = class_getInstanceMethod(class_addr, sel_name);
                int num_args = method_getNumberOfArguments(method);
                char method_name[128] = {0};
                char sel_name_tmp[128] = {0};
                char *x;
                char *y;
                x = sel_name_tmp;
                strcpy(sel_name_tmp, sel_name);
                if(!strchr(x, ':')) {
                    printf("thread-id: %ld | %s [%s %s]\n", threadstack->thread_id, decollators, class_name, sel_name_tmp);
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
                printf("thread-id: %ld | %s [%s %s]\n", threadstack->thread_id, decollators, class_name, method_name);
            }
#endif
        }
    }
}
```

既然大家都喜欢搞 WeChat, 那以 WeChat 撤回消息举个例子, 整个撤回大概是这么个流程. 这里感谢庆总的 [MonkeyDev](https://github.com/AloneMonkey/MonkeyDev), 可以快速测试 WeChat, 之后应该会将该工具移植到 [MonkeyDev](https://github.com/AloneMonkey/MonkeyDev).

那么其实在这里已经可以看出具体的逻辑了, 下面可能用 `awk` 处理了一下更清楚了.

```
2017-09-05 15:04:29.382925+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController MessageReturn:MessageInfo:Event:]
2017-09-05 15:04:29.392743+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_BaseMsgContentViewController OnMsgRevoked:n64MsgId:SysMsg:]
2017-09-05 15:04:29.392994+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------ [NSKVONotifying_BaseMsgContentViewController GetContact]
2017-09-05 15:04:29.517825+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController MessageReturn:MessageInfo:Event:]
2017-09-05 15:04:29.524797+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
2017-09-05 15:04:29.525046+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController addMessageNode:layout:addMoreMsg:]
2017-09-05 15:04:29.525195+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
2017-09-05 15:04:29.525369+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
2017-09-05 15:04:29.526230+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
2017-09-05 15:04:29.526389+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
2017-09-05 15:04:29.526518+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_BaseMsgContentViewController getTipsHeight]
2017-09-05 15:04:29.526577+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
2017-09-05 15:04:29.526628+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
2017-09-05 15:04:29.526740+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
2017-09-05 15:04:29.526839+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
2017-09-05 15:04:29.526897+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_BaseMsgContentViewController getTipsHeight]
2017-09-05 15:04:29.526948+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
2017-09-05 15:04:29.526999+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
2017-09-05 15:04:29.527064+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController isShowHeadImage:]
2017-09-05 15:04:29.527435+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getMessageChatContactByMessageWrap:]
2017-09-05 15:04:29.529299+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
2017-09-05 15:04:29.540957+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:29.607821+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_BaseMsgContentViewController didFinishedLoading:]
2017-09-05 15:04:29.608005+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController ScrollToBottomAnimated:]
2017-09-05 15:04:29.609417+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
2017-09-05 15:04:29.609570+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------------------------------------------- [NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
2017-09-05 15:04:29.609650+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------------------------------------------- [NSKVONotifying_BaseMsgContentViewController getTipsHeight]
2017-09-05 15:04:29.609720+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
2017-09-05 15:04:29.609791+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
2017-09-05 15:04:29.657073+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_NewMainFrameViewController updateSession:]
2017-09-05 15:04:29.661082+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_NewMainFrameViewController reloadSessions]
2017-09-05 15:04:29.670737+0800 WeChat[48799:11942594] [WC] WCSession is not paired
2017-09-05 15:04:29.672210+0800 WeChat[48799:11942594] [WC] -[WCSession onqueue_notifyOfUserInfoError:withUserInfoTransfer:]_block_invoke dropping as pairingIDs no longer match. pairingID (null), client pairingID: (null)
2017-09-05 15:04:29.673883+0800 WeChat[48799:11942591] [WC] no pairingID
2017-09-05 15:04:29.695792+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_NewMainFrameViewController updateStatusBar]
2017-09-05 15:04:29.696051+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------- [NSKVONotifying_NewMainFrameViewController updateSession:]
2017-09-05 15:04:29.699496+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_NewMainFrameViewController reloadSessions]
2017-09-05 15:04:29.755781+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_NewMainFrameViewController updateStatusBar]
2017-09-05 15:04:29.756042+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------ [NSKVONotifying_NewMainFrameViewController updateSession:]
2017-09-05 15:04:29.759650+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_NewMainFrameViewController reloadSessions]
2017-09-05 15:04:29.771645+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.777169+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.782692+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.792774+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.798065+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.803573+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.813564+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.818924+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.824741+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.830379+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.839838+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.844709+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.854562+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.860159+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------------------------------------------ [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.886389+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------- [NSKVONotifying_BaseMsgContentViewController deleteNode:withDB:animated:]
2017-09-05 15:04:29.886569+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------ [NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
2017-09-05 15:04:29.886825+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------ [NSKVONotifying_BaseMsgContentViewController findNodeIndexByLocalId:]
2017-09-05 15:04:29.887270+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------ [NSKVONotifying_BaseMsgContentViewController removeObjectsFromMessageNodeDatas:]
2017-09-05 15:04:29.887521+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_BaseMsgContentViewController getLastSentMsg]
2017-09-05 15:04:29.888255+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_BaseMsgContentViewController updateMessageNodeStatus:]
2017-09-05 15:04:29.888334+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
2017-09-05 15:04:29.919073+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------------------------------------- [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.924847+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------------------------------------------- [NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
2017-09-05 15:04:29.994115+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------ [NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
2017-09-05 15:04:29.994933+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------ [NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
2017-09-05 15:04:29.995051+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
2017-09-05 15:04:29.995115+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_BaseMsgContentViewController getTipsHeight]
2017-09-05 15:04:29.995168+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
2017-09-05 15:04:29.995220+0800 WeChat[48799:11942122] thread-id: 7123647296 | ------------------ [NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
2017-09-05 15:04:30.000301+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:30.000701+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:30.001095+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:30.001367+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:30.001725+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------------- [NSKVONotifying_BaseMsgContentViewController getContentViewY]
2017-09-05 15:04:46.929071+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_NewMainFrameViewController updateAllItemTimeLabel]
2017-09-05 15:05:46.924535+0800 WeChat[48799:11942122] thread-id: 7123647296 | --------------- [NSKVONotifying_NewMainFrameViewController updateAllItemTimeLabel]
```

其实整个过程在 xcode 的控制台下还是很清楚, 有同学可以再做一下输出的优化, 这里我直接用 `awk` 处理下.


```
------------------[NSKVONotifying_BaseMsgContentViewController MessageReturn:MessageInfo:Event:]
---------------------------[NSKVONotifying_BaseMsgContentViewController OnMsgRevoked:n64MsgId:SysMsg:]
------------------------------[NSKVONotifying_BaseMsgContentViewController GetContact]
------------------[NSKVONotifying_BaseMsgContentViewController MessageReturn:MessageInfo:Event:]
------------------[NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
------------------[NSKVONotifying_BaseMsgContentViewController addMessageNode:layout:addMoreMsg:]
---------------------[NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
---------------------[NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
---------------------[NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
------------------------[NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
------------------------[NSKVONotifying_BaseMsgContentViewController getTipsHeight]
---------------------------[NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
---------------------------[NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
---------------------[NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
------------------------[NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
------------------------[NSKVONotifying_BaseMsgContentViewController getTipsHeight]
---------------------------[NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
---------------------------[NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
---------------------[NSKVONotifying_BaseMsgContentViewController isShowHeadImage:]
---------------------[NSKVONotifying_BaseMsgContentViewController getMessageChatContactByMessageWrap:]
---------------------[NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
------------------------[NSKVONotifying_BaseMsgContentViewController didFinishedLoading:]
---------------------[NSKVONotifying_BaseMsgContentViewController ScrollToBottomAnimated:]
------------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
---------------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
---------------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController getTipsHeight]
------------------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
------------------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
------------------------[NSKVONotifying_NewMainFrameViewController updateSession:]
---------------------[NSKVONotifying_NewMainFrameViewController reloadSessions]
notpaired 
droppingas pairingIDs
 
---------------------------[NSKVONotifying_NewMainFrameViewController updateStatusBar]
---------------------------[NSKVONotifying_NewMainFrameViewController updateSession:]
------------------------[NSKVONotifying_NewMainFrameViewController reloadSessions]
------------------------[NSKVONotifying_NewMainFrameViewController updateStatusBar]
------------------------[NSKVONotifying_NewMainFrameViewController updateSession:]
---------------------[NSKVONotifying_NewMainFrameViewController reloadSessions]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
---------[NSKVONotifying_BaseMsgContentViewController deleteNode:withDB:animated:]
------------[NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
------------[NSKVONotifying_BaseMsgContentViewController findNodeIndexByLocalId:]
------------[NSKVONotifying_BaseMsgContentViewController removeObjectsFromMessageNodeDatas:]
---------------[NSKVONotifying_BaseMsgContentViewController getLastSentMsg]
---------------[NSKVONotifying_BaseMsgContentViewController updateMessageNodeStatus:]
------------------[NSKVONotifying_BaseMsgContentViewController findNodeDataByLocalId:]
---------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
---------------------------------------------------------[NSKVONotifying_BaseMsgContentViewController makeCell:indexPath:]
------------[NSKVONotifying_BaseMsgContentViewController getCurContentSizeHeight]
------------[NSKVONotifying_BaseMsgContentViewController getTableViewVisibleHeightWithOrientation:]
---------------[NSKVONotifying_BaseMsgContentViewController getSearchBarHeight]
---------------[NSKVONotifying_BaseMsgContentViewController getTipsHeight]
------------------[NSKVONotifying_BaseMsgContentViewController getAddFriendTipHeight]
------------------[NSKVONotifying_BaseMsgContentViewController getSecurityBannerTipHeight]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
---------------------[NSKVONotifying_BaseMsgContentViewController getContentViewY]
---------------[NSKVONotifying_NewMainFrameViewController updateAllItemTimeLabel]
---------------[NSKVONotifying_NewMainFrameViewController updateAllItemTimeLabel]

```