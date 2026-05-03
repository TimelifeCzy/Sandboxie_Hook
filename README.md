# Sandboxie_Hook

`Sandboxie_Hook` 是一个独立工程，目标是参考 Sandboxie 的低级注入思路，完成一套基于 `LdrInitializeThunk` / `LdrLoadDll` 的启动期注入链路。

它不是 Sandboxie 原工程的裁剪版，也不依赖 Sandboxie 的 ALPC 通信。当前工程使用的是：

- 驱动层 `PsSetCreateProcessNotifyRoutineEx` 监听进程创建
- MiniFilter / MiniPort 负责内核到应用层通知
- `AssistInject.exe` 在用户层接收通知并触发 `lowlevel` 注入
- `low/inject.c` 在目标进程内执行二阶段 DLL 装载

## 工程说明

- `driver/`
  负责进程创建通知、目标过滤、MiniPort 通知以及驱动设备控制。
- `AssistInject/`
  负责连接 MiniPort、读取配置、接收进程启动消息，并调用 `lowlevel_inject.cpp` 发起注入。
- `low/`
  低级注入载荷。核心逻辑是在目标进程启动早期改写 `LdrInitializeThunk`，让目标进程先执行注入代码，再恢复原始流程。

## 当前流程

1. 驱动启动后注册 `PsSetCreateProcessNotifyRoutineEx`。
2. 命中配置的目标进程后，驱动记录 `pid`、父进程、创建时间、镜像路径。
3. 驱动通过 MiniPort 把进程信息发给 `AssistInject.exe`。
4. `AssistInject.exe` 收到消息后，调用 `LowLevelInjectProcess`。
5. `lowlevel_inject.cpp` 复制 `low/` 里的低级载荷到目标进程，并改写目标进程的 `LdrInitializeThunk`。
6. 目标进程首次进入用户态初始化时，先执行 `low/inject.c` 中的注入逻辑。
7. `low/inject.c` 在目标进程内调用 `LdrLoadDll` 装载二阶段 DLL，再调用约定入口，最后恢复原始执行流。

## DLL 替换位置

当前代码仍沿用 `SbieDll.dll` 这一命名和入口约定。如果你后续要换成自己的 DLL，主要看这两个位置：

- `AssistInject/lowlevel_inject.cpp`
  这里构造写入目标进程的数据区，包含 native / wow64 / arm64ec 三套 DLL 路径字符串。
- `low/inject.c`
  这里真正调用 `LdrLoadDll` 装载二阶段 DLL，并通过 `LdrGetProcedureAddress` 获取入口后执行。

如果你不再使用 ordinal `1` 作为入口，这里也需要一起改。

## 构建

建议环境：

- Visual Studio 2019
- Toolset: `v142`
- 以解决方案 `LibSandboxieHook.sln` 构建

如果只验证用户层注入逻辑，也可以单独编译：

- `AssistInject/AssistInject.vcxproj`
