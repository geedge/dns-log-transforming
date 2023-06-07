from socket import timeout
import traceback
from confluent_kafka import Consumer, KafkaException
from confluent_kafka import Producer 
import json
import logging
import collections
import traceback
import time
import datetime
import os
#logging.basicConfig(filename='/home/zjh/code/code_py/dns_new_behavior_log', level=logging.ERROR,
#     format='%(asctime)s - %(levelname)s - %(message)s')

def serialize(data):
    return json.dumps(data).encode('utf-8')

def deserialize(data):
    return json.loads(data.decode('latin-1'))

#初始化 一次域名解析采集请求获取到的原始解析记录列表
def Init_items_json():
    message = collections.OrderedDict()
    message["qname"] = ""
    message["ttl"] = ""
    message["class"] = ""
    message["type"] = ""
    message["value"] = ""
    return message
# CLASS域
class_dict = {
    1:"IN",
    2:"CS",
    3:"CH",
    4:"HS"
}
# TYPE域
type_dict = {
    1:"A",
    2:"NS",
    3:"MD",
    4:"MF",
    5:"CNAME",
    6:"SOA",
    7:"MB",
    8:"MG",
    9:"MR",
    10:"NULL",
    11:"WKS",
    12:"PTR",
    13:"HINFO",
    14:"MINFO",
    15:"MX",
    16:"TXT",
    17:"RP",
    18:"AFSDB",
    19:"X25",
    20:"ISDN",
    21:"RT",
    22:"NSAP",
    23:"NSAP-PTR",
    24:"SIG",
    25:"KEY",
    26:"PX",
    27:"GPOS",
    28:"AAAA",
    29:"LOC",
    30:"NXT",
    31:"EID",
    32:"NIMLOC",
    33:"SRV",
    34:"ATMA",
    35:"NAPTR",
    36:"KX",
    37:"CERT",
    38:"A6",
    39:"DNAME",
    40:"SINK",
    41:"OPT",
    42:"APL",
    43:"DS",
    44:"SSHFP",
    45:"IPSECKEY",
    46:"RRSIG",
    47:"NSEC",
    48:"DNSKEY",
    49:"DHCID",
}
#初始化新域名解析行为数据格式
def Init_new_behavior_json():
    message = collections.OrderedDict()
    message["region"] = "beijing"
    message["timestamp_msg"] = ""
    message["timestamp"] = ""
    message["addr_type"] = -1
    message["s_ip"] = ""
    message["s_port"] = -1
    message["d_ip"] = ""
    message["d_port"] = -1
    message["transaction_id"] = -1
    message["flags"] = -1
    message["origin_domain"] = ""
    message["qr_class"] = ""
    message["qr_type"] = ""
    message["answer_rrs"] = 0
    message["authority_rrs"] = 0
    message["additional_rrs"] = 0
    message["answers"] = []
    message["auth_ns"] = []
    message["additional_res"] = []
    message["dns_sub"] = -1
    return message

def transfer_new_behavior_json(result,message):
    result["timestamp_msg"] = str(int(round(time.time() * 1000)))
    if 'common_data_center' in message:
        result["region"] = str(message['common_data_center'])
    if 'common_end_time' in message:
        result["timestamp"] = str(message['common_end_time'])
    if 'common_address_type' in message:
        result["addr_type"] = int(message['common_address_type'])
    #数据包为应答包，源IP为服务器，目的IP为客户端
    if 'common_client_ip' in message:
        result["d_ip"] = str(message['common_client_ip'])
    if 'common_client_port' in message:
        result["d_port"] = int(message['common_client_port'])
    if 'common_server_ip' in message:
        result["s_ip"] = str(message['common_server_ip'])
    if 'common_server_port' in message:
        result["s_port"] = int(message['common_server_port'])
    if 'dns_message_id' in message:
        result["transaction_id"] = int(message['dns_message_id'])
    if 'dns_qname' in message:
        if(len(message['dns_qname'])==0):
            result["origin_domain"] = str(message['dns_qname'])
        else:
            result["origin_domain"] = str(message['dns_qname']+".")
    if 'dns_ancount' in message:
        result["answer_rrs"] = int(message['dns_ancount'])
    if 'dns_nscount' in message:
        result["authority_rrs"] = int(message['dns_nscount'])
    if 'dns_arcount' in message:
        result["additional_rrs"] = int(message['dns_arcount'])
    '''
    flags [dns_qr(1),dns_opcode(4),dns_aa(1),dns_tc(1),dns_rd(1),dns_ra(1),0,0,0,dns_rcode(4)]
    '''
    if 'dns_qr' in message:
        dns_qr = message['dns_qr']
    if 'dns_opcode' in message:
        dns_opcode = message['dns_opcode']
    if 'dns_aa' in message:
        dns_aa = message['dns_aa']
    if 'dns_tc' in message:
        dns_tc = message['dns_tc']
    if 'dns_rd' in message:
        dns_rd = message['dns_rd']
    if 'dns_ra' in message:
        dns_ra = message['dns_ra']
    if 'dns_rcode' in message:
        dns_rcode = message['dns_rcode']
    result['flags'] = dns_rcode+(dns_ra<<7)+(dns_rd<<8)+(dns_tc<<9)+(dns_aa<<10)+(dns_opcode<<11)+(dns_qr<<15)


    if 'dns_qclass' in message:
        if message['dns_qclass'] in class_dict:
            result["qr_class"] = class_dict[message['dns_qclass']]
    if 'dns_qtype' in message:
        if message['dns_qtype'] in type_dict:
            result["qr_type"] = type_dict[message['dns_qtype']]
    if 'dns_sub' in message:
        result["dns_sub"] = int(message['dns_sub'])
    if 'dns_rr' in message:
        dns_rr = json.loads(message['dns_rr'])
        dns_rr = dns_rr['rr']
        item_num = 0
        for item in dns_rr:            
            if 'type' in item:
                item_num = item_num + 1
                item_analysis = Init_items_json()
                if 'name' in item:
                    if(len(item['name'])==0):
                        item_analysis['qname'] = str(item['name'])
                    else:
                        item_analysis['qname'] = str(item['name']+".")
                if 'ttl' in item:
                    item_analysis['ttl'] = str(item['ttl'])
                if 'class' in item:
                    if item['class'] in class_dict:
                        item_analysis['class'] = class_dict[item['class']]
                    '''
                    answers:域名解析采集请求获取到的原始解析记录列表
                    '''
                if(item['type'] == 1):
                    item_analysis['type'] = "A"
                    if 'a' in item:
                        item_analysis['value'] = str(item['a'])
                        if(item_num <= result["answer_rrs"]):
                            result['answers'].append(item_analysis)
                        if(item_num > result["answer_rrs"] + result["authority_rrs"]):
                            result['additional_res'].append(item_analysis)
                elif(item['type'] == 28):
                    item_analysis['type'] = "AAAA"
                    if 'aaaa' in item:
                        item_analysis['value'] = str(item['aaaa'])
                        if(item_num <= result["answer_rrs"]):
                            result['answers'].append(item_analysis)
                        if(item_num > result["answer_rrs"] + result["authority_rrs"]):
                            result['additional_res'].append(item_analysis)
                elif(item['type'] == 5):
                    item_analysis['type'] = "CNAME"
                    if 'cname' in item:
                        if(len(item['cname'])==0):
                            item_analysis['value'] = str(item['cname'])
                        else:
                            item_analysis['value'] = str(item['cname']+".")
                        if(item_num < result["answer_rrs"]):
                            result['answers'].append(item_analysis)
                elif(item['type'] == 12):
                    item_analysis['type'] = "PTR"
                    if 'ptr' in item:
                        if(len(item['ptr'])==0):
                            item_analysis['value'] = str(item['ptr'])
                        else:
                            item_analysis['value'] = str(item['ptr']+".")
                        if(item_num < result["answer_rrs"]):
                            result['answers'].append(item_analysis)
                    '''
                    auth_ns:域名请求过程中，获取的权威域名服务器相关信息列表，主要指NS记录
                    '''
                elif(item['type'] == 2):
                    item_analysis['type'] = "NS"
                    if 'ns' in item:
                        if(len(item['ns'])==0):
                            item_analysis['value'] = str(item['ns'])
                        else:
                            item_analysis['value'] = str(item['ns']+".")
                        result['auth_ns'].append(item_analysis)
                else:
                    #item_analysis['type'] = item['type']
                    continue
   # print("answer"+str(result["answer_rrs"]))
   # print("auth"+str(result["authority_rrs"]))
   # print("add"+str(result["additional_rrs"]))
   # print("itemnum"+str(item_num))
    result["answer_rrs"] = len(result["answers"])
    result["authority_rrs"] = len(result["auth_ns"])
    result["additional_rrs"] = len(result["additional_res"])
    return result

if __name__ == "__main__":
    #消费者配置
    conf_consumer = {'bootstrap.servers': '159.226.16.97:9092', 'group.id': 'dns-behavior',
             'auto.offset.reset': 'latest'}
    #生产者配置
    conf_producer = {'bootstrap.servers':'159.226.16.115:29097,159.226.16.116:29097,159.226.16.116:29090,159.226.16.116:29091,159.226.16.116:29092','enable.idempotence':1,'acks':"all",'max.in.flight':1,'retries':3,'linger.ms':5}
    #幂等写入的设置参考： https://leftasexercise.com/2020/07/03/learning-kafka-with-python-retries-and-idempotent-writes/   

    #初始化生产者和消费者
    consumer = Consumer(conf_consumer)
    consumer.subscribe(['TRANSACTION-RECORD'])

    TOPIC="DNS_BEHAVIOR_2022"
    producer = Producer(conf_producer)
   
    recv_num = 0
    send_num = 0
    start_time = int(time.mktime(datetime.date.today().timetuple()))
    last_time = start_time
    rjs_send_time = int(time.time())
    rjs_send_num = 0
    try:
        while True:
            if(int(time.time())-rjs_send_time == 10800):
                rjs_send_time = rjs_send_time + 10800
                print(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))
                print("send num is :"+str(rjs_send_num))
                rjs_send_num = 0
            if(int(time.time())-last_time == 86400):
                last_time = last_time + 86400
                print(str(datetime.date.today())+"\n")
                print("recv_num is: "+str(recv_num))
                print("send_num is: "+str(send_num))
                recv_num = 0
                send_num = 0
            producer.poll(0)
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                raise KafkaException(msg.error())
            else:
                message = deserialize(msg.value())
                behavior_data = Init_new_behavior_json()
                if 'common_schema_type' in message:
                    if (message['common_schema_type'] == 'DNS'):
                        if 'dns_qr' in message:
                            if(message['dns_qr'] == 1):
                               # with open('recv_data','a') as recv_file:
                                   # recv_file.write(str(message)+'\n')
                                recv_num = recv_num + 1
                                behavior_result = transfer_new_behavior_json(behavior_data,message)
                                if(len(behavior_result['origin_domain'])==0):
                                    continue
                                elif(len(behavior_result['qr_class'])==0):
                                    continue
                                elif(len(behavior_result['qr_type'])==0):
                                    continue
                                elif(behavior_result['s_port']!=53):
                                    continue
                                else:
                                    try:
                                        producer.poll(0)
                                        producer.produce(TOPIC,serialize(behavior_result))
                                        send_num = send_num + 1
                                        rjs_send_num = rjs_send_num + 1
                                      #  with open('send_data','a') as send_file:
                                            #send_file.write(str(behavior_result)+'\n')
                                        #if(recv_num < 10000):
                                         #   print(behavior_result)
                                    except BufferError as bfer:
                                        traceback.print_exc()
                                        producer.poll(0.1)
                                    

                                 
    except Exception as e:
        traceback.print_exc()
    finally:
        consumer.close()
        producer.flush()






