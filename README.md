# runc_code_analysis
runC是一个根据OCI标准创建并运行容器的工具，这个项目是分析runC的代码实现

> 容器的工业级标准化组织OCI(Open Container Initiative)出炉，这是业界大佬为避免容器生态和docker耦合过紧做的努力，也是docker做出的妥协
> 随着docker等容器引擎自身功能越来越丰富，其逐渐呈现出组件化的趋势（将底层交给OCI，自己则专注网络，配置管理，集群，编排，安全等方面）
> 内核中关于容器的开发也如火如荼，包括 capabilities, fs, net, uevent等和容器相关的子系统

以runc run为例，分析
- runc的bootstrap阶段
- runc的Init阶段
