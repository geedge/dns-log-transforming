## 项目介绍

目标：将科技网TSG格式的DNS日志转成软件所定义的DNS日志格式

* 输入：科技网DNS日志：

  * 日志来源：科技网159.226.16.97服务器(kafka-topic:TRANSACTION-RECORD)

  * 访问方式：（若访问方式更新，请询问王道宽）
    	* 通过easyconnect连接科技网；VPN连接方式见：https://docs.mesalab.cn/pages/viewpage.action?pageId=24216380（账号：zhuyujia@iie.ac.cn   密码：JiShuShi@20230410；需要朱宇佳老师的手机验证码）
    * 远程登录159.226.16.96服务器（账户及密码需要通过钉钉审批-科技网服务器使用权限申请），登录端口为：10022
    * 在159.226.16.96服务器ssh登录159.226.16.97服务器，端口为：10022 账户及密码同上		
    * 通过./kafka-console-consumer.sh --bootstrap-server 159.226.16.97:9092 --topic TRANSACTION-RECORD访问科技网DNS日志
    
* 输出：软件所kafka集群：'159.226.16.115:29097,159.226.16.116:29097,159.226.16.116:29090,159.226.16.116:29091,159.226.16.116:29092'
  * topic:
    * "DNS-NEW-RR-LOG"：对应附件1-2.1. 域名资源记录数据格式定义
    * "DNS_BEHAVIOR_2022"：对应附件1-2.2. 域名访问行为记录数据格式定义-新域名解析行为数据格式
* 代码

 	1. "DNS-NEW-RR-LOG"对应代码：159.226.16.97：/home/zhijinghua/dnslog_handling/code/dnslog_resource_hr_v4.py
 	2. "DNS_BEHAVIOR_2022"对应代码：159.226.16.97：/home/zhijinghua/dnslog_handling/code/dnslog_behavior_hr_v4.py
 	3. 代码说明：
 	 1.完成日志格式转换
 	 2.过滤了部分流量：过滤内容见“DNS日志转化代码说明.docx”
 	 3.日志统计：在发送日志到软件所的kafka时记录的
 	 * 地址：159.226.16.97：/home/zhijinghua/dnslog_handling/behavior_out_test
 	 * 说明：每天结束记录一次日志量；每三个小时记录一次日志量
 	   以2022-08-18（输出的是2022.08.17整天的日志量）为例
 	   recv_num is: 66843578（从TRANSACTION-RECORD读取的日志量）
 	   send_num is: 64855245（格式转换和过滤后发送到DNS_BEHAVIOR_2022的日志量）

## 相关材料

1. 科技网TSG格式：https://docs.mesalab.cn/pages/viewpage.action?pageId=693965
2. 软件所转换格式：项目数据格式与交互接口定义-V3.2-20220719.docx
3. DNS日志转化代码说明.docx