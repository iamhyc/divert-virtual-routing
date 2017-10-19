### NDIS, Network Driver Interface Specification

* L1: ***微端口驱动***
  * 直接操作物理网卡

- L2: ***NDIS中间驱动***
  - 可以拦截数据包，实现复合网卡的功能
- L3: ***协议驱动***
  - 如tcpip.sys处理ip包
    - Tcpip.sys创建了几个设备对象，/Device/RawIp，/Device/Udp，/Device/Tcp，/Device/Ip，/Device/MULTICAST来接收TDI Client的IRP请求包
  - 所有协议同层不分级

开发标准的设备过滤驱动程序，挂载到这些标准设备栈上，拦截IRP命令，就能实现网络数据包的拦截修改等功能



### NDSI HOOK

