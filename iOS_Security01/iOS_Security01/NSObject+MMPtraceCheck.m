//
//  NSObject+MMPtraceCheck.m
//  iOS_Security01
//
//  Created by zhai shuqing on 2020/1/21.
//  Copyright © 2020 ymg. All rights reserved.
//

#import "NSObject+MMPtraceCheck.h"
#import "fishhook.h"
#import <sys/sysctl.h>

@implementation NSObject (MMPtraceCheck)

//原始函数*
int (* sysctl_p)(int *, u_int, void *, size_t *, void *, size_t);

//fishhook后函数
int mmSysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize){
    if(namelen == 4
       && name[0] == CTL_KERN
       && name[1] == KERN_PROC
       && name[2] == KERN_PROC_PID
       && info
       ){
        int err = sysctl_p(name,namelen,info,infosize,newinfo,newinfosize);
        //Get info
        struct kinfo_proc *myinfo = (struct kinfo_proc *)info;
        if((myinfo->kp_proc.p_flag & P_TRACED) !=0){ //存在调试
            exit(0);
        }
        return err;
    }
    //执行原C语言系统函数sysctl
    return sysctl_p(name,namelen,info,infosize,newinfo,newinfosize);
}

+ (void)load{
    rebind_symbols((struct rebinding[1]){{"sysctl",mmSysctl,(void *)&sysctl_p}}, 1);
}

@end
