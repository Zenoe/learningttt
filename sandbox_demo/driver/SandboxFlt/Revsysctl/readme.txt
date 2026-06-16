当前实现里 set <PID> 的 PID 必须已经在 SandboxFlt 的 PID 表里。
通常就是由 sandbox_demo 以 Launch SANDBOXED 启动后注册进去的 root PID，或者它继承出来的子进程 PID。普通外部进程、手工启动的进程、或者还没被 sandbox_demo 调用 IOCTL_SANDBOX_ADD_PROCESS 注册的 PID，都会返回 1168 / ERROR_NOT_FOUND。
你可以先查：
.\RevDrvCtl.exe list
然后从输出里选一个 Box 是 Box00 的 root PID 或 tracked PID，再执行：
.\RevDrvCtl.exe set <PID> 10.8.0.4 Box00
另外注意两点：
Box00 必须和 list 里显示的 box 名完全一致；如果不确定，可以先不传 box 名：.\RevDrvCtl.exe set 6920 10.8.0.4