from socket import timeout
import traceback
from confluent_kafka import Consumer, KafkaException
from confluent_kafka import Producer 
import json
import logging
import collections
import traceback

#logging.basicConfig(filename='/home/zjh/code/code_py/dns_new_resource_log', level=logging.WARNING,
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

#初始化域名资源记录数据格式
def Init_resource_json():
    message = collections.OrderedDict()
    message["source"] = 4
    message["items"] = []
    message["msg_size_rcvd"] = -1
    message["collect_time"] = ""
    message["region"] = "beijing"
    message["query_time"] = -1
    message["when"] = ""
    message["msg_size_req"] = -1
    message["dns_sub"] = -1
    message["qr"] = -1
    message["addr_type"] = -1
    message["qname_count"] = -1
    message["stats_period"] = -1
    message["confidence"] = -1.00
    message["flag"] = -1
    message["request_type"] = 0
    message["answer_type"] = -1
    message["request_result"] = -1
    message["origin_domain"] = ""
    message["type_flag"] = -1
    return message
#将科技网日志格式转化成软件所定义格式
def transfer_resource_json(result,message):
    '''
    type_flag-----[A,AAAA,CNAME,PTR,SRV,SOA,TXT,NS]对应的位置逆序按位取1/0（包含该记录则取1，否则取0）与dns_qtype有关
    reverse_typeflag ------[NS,TXT,SOA,SRV,PTR,CNAME,AAAA,A]
    '''
    reverse_typeflag = 0
    if 'common_s2c_byte_num' in message:
        result["msg_size_rcvd"] = int(message['common_s2c_byte_num'])
    if 'common_end_time' in message:
        result["collect_time"] = str(message['common_end_time'])
    if 'common_data_center' in message:
        result["region"] = str(message['common_data_center'])
    if 'common_end_time' in message:
        result["when"] = str(message['common_end_time'])
    if 'common_c2s_byte_num' in message:
        result["msg_size_req"] = int(message['common_c2s_byte_num'])
    if 'dns_sub' in message:
        result["dns_sub"] = int(message['dns_sub'])
    if 'dns_qr' in message:
        result["qr"] = int(message['dns_qr'])
    if 'common_address_type' in message:
        result["addr_type"] = int(message['common_address_type'])
    if 'dns_qname' in message:
        if(len(message['dns_qname'])==0):
            result["origin_domain"] = str(message['dns_qname'])
        else:
            result["origin_domain"] = str(message['dns_qname']+".")

    if 'dns_rr' in message:
        dns_rr = json.loads(message['dns_rr'])
        dns_rr = dns_rr['rr']
        for item in dns_rr:
            if 'type' in item:
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
                if(item['type'] == 1):
                    item_analysis['type'] = "A"
                    if((reverse_typeflag&1)==0):
                        reverse_typeflag = reverse_typeflag+1
                    if 'a' in item:
                        item_analysis['value'] = str(item['a'])
                elif(item['type'] == 28):
                    item_analysis['type'] = "AAAA"
                    if((reverse_typeflag&(1<<1))==0):
                        reverse_typeflag = reverse_typeflag+(1<<1)
                    if 'aaaa' in item:
                        item_analysis['value'] = str(item['aaaa'])
                elif(item['type'] == 5):
                    item_analysis['type'] = "CNAME"
                    if((reverse_typeflag&(1<<2))==0):
                        reverse_typeflag = reverse_typeflag+(1<<2)
                    if 'cname' in item:
                        if(len(item['cname'])==0):
                            item_analysis['value'] = str(item['cname'])
                        else:
                            item_analysis['value'] = str(item['cname']+".")
                elif(item['type'] == 12):
                    item_analysis['type'] = "PTR"
                    if((reverse_typeflag&(1<<3))==0):
                        reverse_typeflag = reverse_typeflag+(1<<3)
                    if 'ptr' in item:
                        if(len(item['ptr'])==0):
                            item_analysis['value'] = str(item['ptr'])
                        else:
                            item_analysis['value'] = str(item['ptr']+".")
                elif(item['type'] == 33):
                    item_analysis['type'] = "SRV"
                    if((reverse_typeflag&(1<<4))==0):
                        reverse_typeflag = reverse_typeflag+(1<<4)
                    if 'name' in item:
                        if(len(item['name'])==0):
                            item_analysis['value'] = str(item['name'])
                        else:
                            item_analysis['value'] = str(item['name']+".")
                elif(item['type'] == 6):
                    item_analysis['type'] = "SOA"
                    if((reverse_typeflag&(1<<5))==0):
                        reverse_typeflag = reverse_typeflag+(1<<5)
                    if 'mname' in item:
                        if(len(item['mname'])==0):
                            item_analysis['value'] = str(item['mname'])
                        else:
                            item_analysis['value'] = str(item['mname']+".")#MNAME	名称服务器的 <domain-name>，该名称服务器是这个区域的数据起源或主要源。
                elif(item['type'] == 16):
                    item_analysis['type'] = "TXT"
                    if((reverse_typeflag&(1<<6))==0):
                        reverse_typeflag = reverse_typeflag+(1<<6)
                    if 'txt' in item:
                        item_analysis['value'] = str(item['txt'])
                elif(item['type'] == 2):
                    item_analysis['type'] = "NS"
                    if((reverse_typeflag&(1<<7))==0):
                        reverse_typeflag = reverse_typeflag+(1<<7)
                    if 'ns' in item:
                        if(len(item['ns'])==0):
                            item_analysis['value'] = str(item['ns'])
                        else:
                            item_analysis['value'] = str(item['ns']+".")
                else:
                    #item_analysis['type'] = item['type']
                    continue

                result['items'].append(item_analysis)

    result["type_flag"] = reverse_typeflag

    return result

if __name__ == "__main__":
    #消费者配置
    conf_consumer = {'bootstrap.servers': '159.226.16.97:9092', 'group.id': 'dns-resource',
             'auto.offset.reset': 'latest'}#earliest
    #生产者配置
    conf_producer = {'bootstrap.servers':'159.226.16.115:29097,159.226.16.116:29097,159.226.16.116:29090,159.226.16.116:29091,159.226.16.116:29092','enable.idempotence':1,
    'acks':"all",'max.in.flight':1,'retries':3,'linger.ms':5}
    #幂等写入的设置参考： https://leftasexercise.com/2020/07/03/learning-kafka-with-python-retries-and-idempotent-writes/   

    #初始化生产者和消费者
    consumer = Consumer(conf_consumer)
    consumer.subscribe(['TRANSACTION-RECORD'])

    TOPIC="DNS-NEW-RR-LOG"
    producer = Producer(conf_producer)

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                raise KafkaException(msg.error())
            else:
                message = deserialize(msg.value())
                #print(deserialize(message))
                source_data = Init_resource_json()
                if 'common_schema_type' in message:
                    if (message['common_schema_type'] == 'DNS'):
                        if 'dns_qr' in message:
                            if(message['dns_qr'] == 1):
                                source_result = transfer_resource_json(source_data,message)
                                if(len(source_result['items'])==0):
                                    continue
                                if(len(source_result['origin_domain'])==0):
                                    continue
                                else:
                                    try:
                                        producer.poll(0)
                                        producer.produce(TOPIC,serialize(source_result))
                                    except BufferError as bfer:
                                        traceback.print_exc()
                                        producer.poll(0.1)
    except Exception as e:
        traceback.print_exc()
    finally:
        consumer.close()
        producer.flush()
