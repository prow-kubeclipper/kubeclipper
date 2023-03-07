# KubeClipper 部署

- [KubeClipper 部署](https://wt0h8qi4nj.feishu.cn/docs/doccntErmtnH0i0TGojYlQJyFpf)
- 插件部署
    - [NFS](#NFS)

## 集群规格（生产环境）

| 节点 | CPU | RAM | root disk | etcd（SSD）| kubelet（> container runtime）| container runtime |
| --- | --- | --- | --- | --- | --- | --- |
| host（kc-server）\* 3 | 4C+ | 8G+ | 100GB | 40GB | 250GB+ | 250GB+ |
| agent（kc-agent）\* N | 16C+ | 32G+ | 100GB | 40GB | 250GB+ | 250GB+ |

## NFS

如果集群将对接 NFS 存储，**需要在所有节点上提前安装 nfs-utils**。

1. 下载 <http://tarballs.99cloud.com.cn/kubeclipper/nfs/nfs-v4.0.2-x86_64.tar.gz> 并上传至所有节点
1. 解压 `tar -xvzf nfs-v4.0.2-x86_64.tar.gz && cd ${version}`，**根据节点的平台架构（x86_64/aarch64）**cd 至相应的目录
    - **CentOS** 环境下执行 `rpm -ivh --nodeps --replacefiles --replacepkgs *.rpm` 安装 nfs-utils 相关应用程序后执行 `rpm -qi nfs-utils` 检查是否成功安装
