# runc 运行容器 init部分
> 什么是 nsenter，nsenter 是 runc 中的一个 package，它包含了一个特殊的构造函数，用来在 Go runtime 启动之前做一些事情，比如 setns()。
> nsenter 会引入 C 并使用 cgo 实现相关逻辑。在cgo中，如果在 C 的 import 后紧跟注释，则在编译程序包的 C 语言实现部分时，该注释将用作 header。
> 因此，每次 import nsenter 时，nsexec()都会调用 C 函数。在 runc 中只有 init.go import 了 nsenter。
> 容器技术最关键的就是 namespace 和 cgroup，其中 namespace 是通过 setns() 函数来实现的，
> 但是 setns() 有一个问题： A multithreaded process may not change user namespace with setns(). 。
> 而 go runtime 是多线程的，所以需要在 go runtime 启动前执行 setns() 设置好 namespace，然后再走 go 相关实现流程。


在实际的 nsenter 实现中，存在 3 个进程，分别为 parent, child, grandchild。在注释中可以看到 nsenter 实现过程中的考虑：
来看下 parent，child，grandchild 分别做了哪些事情：

- parent
parent 进程通过环境变量 _LIBCONTAINER_INITPIPE 获取相关配置信息，然后 clone 出 child 进程，当 child 进程 ready 之后设置 user map，从 child 进程中接受 grandchild 进程 pid，然后通过管道传递给外层的 runc 进程。parent 进程退出条件为 child 进程和 grandchild 都处于 ready 状态后，parent 进程退出。之所以要 clone child 进程，是因为如果创建了 user namespace，那么 user map 只能由原有的 user namespace 设置，所以需要 clone child 进程，然后在 parent 进程中设置 user map。

- child
child 进程先执行 setns()，在一些老版本的kernel 中，CLONE_PARENT flag 与 CLONE_NEWPID 有冲突，所以使用 unshare 创建 user namespace， user namespace 需要先于其他 namespace 创建，创建 user namespace 并设置 user map，才有能力创建其他的 namespace。等待 parent 进程设置 user map 后，设置 child 当前进程的 uid 为 root(0) ，使用 unshare 创建其他 namespace，然后 clone grandchild 进程，并将 grandchild 进程 pid 传递给 parent，然后退出。之所以要 clone grandchild 进程，是因为在 child 进程中设置 namespace 并不会在 child 进程中生效，所以需要 clone 出一个新的进程，继承 namespace 配置。

- grandchild（init）
grandchild 进程就是容器真正的进程，在确保 parent 和 child 进程都处于 ready 之后，设置 uid,gid，从管道中读取相应配置信息，然后 unshare 创建 cgroup namespace，然后将状态发送给 parent 后 返回。grandchild 进程返回后继续执行 go 代码流程。
