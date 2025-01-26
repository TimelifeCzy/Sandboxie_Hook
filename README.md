# Authorization-Process-Analysis

### 看雪笔记: https://bbs.pediy.com/user-category-819685-21.htm

基于Sandboxie的应用层hook框架，它与detours/minihook/dynamorio 各有优势和劣势。

这是一套完整r3进程监视方案，从Ldr_Init感染而实现整个进程调用监控。

注意：这并非应用层隔离环境分析，请跳转：https://github.com/TimelifeCzy/unicorn_peEmu

Sandboxie: https://github.com/sandboxie/sandboxie

代码使用MiniPort替换ALPC同步通信，Demo使用方式：

1. 手动安装驱动，右击HadesBox.inf安装.
sc query HadesBox(查询) & sc start HadesBox(启动) & sc stop HadesBox(停止)

2. AssistInject.exe同级目录下放置Assistcfg.json文件，启动AssistInject.exe
{
	"processName":"a.exe|b.exe|c.exe"
}

驱动注册PsSetCreateProcessNotifyRoutineEx拦截Assistcfg.json配置的进程启动，进程回调中过滤进程，命中后MinPort通知R3注入(阻塞)，R3注入后完成调用。
