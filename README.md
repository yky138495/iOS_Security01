# iOS_Security01
iOS 安全之-反调试



## fishhook 替换C语言系统函数sysctl

```
+ (void)load{
rebind_symbols((struct rebinding[1]){{"sysctl",mmSysctl,(void *)&sysctl_p}}, 1);
}
```


## fishhook后新函数判断是否存在ptrace调试
```
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
```
