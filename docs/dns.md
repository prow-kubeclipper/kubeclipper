# KubeClipper DNS 设计

[DNS 设计文档](https://zhc3o5gmf9.feishu.cn/docs/doccnCGINvmbvaHt92m8Gl3iQCd)

**实现思路：**

当前实现为直接将解析记录配置到 Corefile 中，主要用到了 CoreDNS 的 [hosts](https://coredns.io/plugins/hosts/) 和 [template](https://coredns.io/plugins/template/) 插件：

* 其中 hosts 插件用于记录普通解析
* template 用于记录泛解析。

**具体流程为：**

dashboard 调用 api 对 record 进行 CRUD 操作，dns controller 根据 event 生成对应 Corefile 并更新到 k8s cluster 中以实现 dns 同步。

> 由于 configmap、corefile、dns 缓存等原因，数据更新大概有 35 秒左右延迟。



## 1. Hosts & Template

### Hosts

hosts 插件类似于修改 /etc/hosts 文件，ip 和域名一一对应，这里用于实现普通解析。

```yaml
a.com:53 {
  errors
  cache 10
	loadbalance
  hosts {
    1.2.3.4 r1.a.com
    2.3.4.5 r1.a.com
    11.22.33.44 r2.a.com
    22.33.44.55 r2.a.com
    fallthrough
    }
	forward . /etc/resolv.conf
}
```



### Template

Template 插件可以通过 Go Template 来组装返回值，同时支持使用正则表达式进行域名匹配，当前用于实现泛解析。

```yaml
b.com:53 {
  errors
  cache 10
	loadbalance
  template IN A b.com {
    match .*\.x\.b\.com
    answer "{{ .Name }} 60 IN A 33.44.55.66"
    answer "{{ .Name }} 60 IN A 44.55.66.77"
    fallthrough
  }
}
```





## 2. 具体细节

### 负载均衡

coredns 的 [loadbalance](https://coredns.io/plugins/loadbalance/) 插件提供了负载均衡功能，Corefile 中添加该插件配置即可。

```yaml
b.com:53 {
	loadbalance # 配置启用 loadbalance 插件
}
```



### 泛解析和普通解析优先级

由于默认 coredns 中 template 插件优先级高于 hosts 插件，导致默认情况下泛解析优先级会高于普通解析。

**当前解决方式如下**：

将普通解析和泛解析分别启动一个服务，普通解析用默认的 53 端口，泛解析用 5300 端口，当 53 端口的普通解析没有记录时 forward 到 5300 端口再走泛解析，以此来提升普通解析的优先级。

```yaml
b.com:53 {
  errors
  cache 10
  loadbalance
  hosts {
    1.2.3.4 r1.b.com
    2.3.4.5 r1.b.com
    fallthrough
  }
  # 这里未匹配到时转发到 5300 端口，由 template 插件继续处理
  forward . 10.96.0.10:5300
}
b.com:5300 {
  errors
  cache 10
  loadbalance
  template IN A b.com {
    match .*\.x\.b\.com
    answer "{{ .Name }} 60 IN A 33.44.55.66"
    answer "{{ .Name }} 60 IN A 44.55.66.77"
    fallthrough
  }
}
```



### 泛解析优先级

多级泛解析之间也存在优先级，比如 *.a.b.com 和 *.b.com。

**当前实现方式如下：**

template 插件可以填充多个配置，多个配置优先级根据配置顺序从上到下，因此在实现时进行了一次排序，根据 rr 长度进行倒叙排列。

例如：

```yaml
b.com:5300 {
  errors
  cache 10
	loadbalance
  template IN A b.com {
    match .*\.x\.b\.com
    answer "{{ .Name }} 60 IN A 33.44.55.66"
    fallthrough
  }
  template IN A b.com {
    match .*\.b\.com
    answer "{{ .Name }} 60 IN A 11.22.33.44"
    fallthrough
  }
}
```

上述配置中， 两个正则表达式都可以匹配 `a.a.b.com`，但是`.*\.x\.b\.com`在前面，因此最终返回结果为`33.44.55.66`。

