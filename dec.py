from base64 import b64decode

from scapy.all import *
import scapy_http.http as http
from Cryptodome.Cipher import AES
import warnings

# warnings.filterwarnings('ignore')

# 第一层：packet，网卡数据
# 第二层：packet.payload，IP数据包
# 第三层：packet.payload.payload，TCP数据包
# 第四层：packet.payload.payload.payload，HTTP数据包
# 第五层：HTTP的响应数据

# AES解密
def dec(text):
    # vi = [0]
    cryptor = AES.new("e45e329feb5d925b".encode(), AES.MODE_CBC, "AES128aaaaaaaaaa".encode())
    t = b64decode(text)
    plain_text = cryptor.decrypt(t)
    return bytes.decode(plain_text).rstrip('\0')


def req_dec(req):
    req = dec(req)
    datap = re.compile(r"ecode\('(.+?)'\)\)")
    data = datap.findall(req)
    if data:
        # print(b64decode(data[0]).decode("utf-8","ignore"))
        datap1 = re.compile(r"cmd=\"(.+?)\"")
        data1 = datap1.findall(b64decode(data[0]).decode("utf-8", "ignore"))
        # print(b64decode(data[0]).decode("utf-8","ignore"))
        if data1:
            return data1[0]
    return None


def res_dec(res):
    res = dec(res)
    datap = re.compile(r"msg\":\"(.+?)\"}")
    data = datap.findall(res)
    if data:
        return b64decode(data[0]).decode("utf-8", "ignore")
    return None


# 获取请求包数据及响应包数据
packets = rdpcap("./d.pcap")
for cnt in range(len(packets)):
    # tmp = packets[cnt].payload.payload.payload.payload
    if "Method" in str(packets[cnt].payload.payload.payload.payload.fields_desc):
        #找到POST类型
        if packets[cnt].payload.payload.payload.payload.Method == b"POST":
            #先检测是否为payload
            #找到其请求包数据对应标号，在其header下一个或下下一个或者无数据，这样判断不准确
            t = cnt
            cnt = cnt + 1
            while not packets[cnt].payload.payload.payload.payload.fields_desc:
                if cnt - t == 2:
                    print("None")
                    continue
                cnt = cnt + 1
            try:
                req_data = raw(packets[cnt].payload.payload.payload.payload[0]).decode("utf-8")
                print("请求数据包："+req_dec(req_data))
            except Exception as e:
                # print("此POST无数据！")
                print(e)
                continue

            #再找对应的响应包，再其下下个或者无响应或冰蝎开始自动获取那个没匹配成功
            cnt = cnt + 2
            try:
                tmp = packets[cnt].payload.payload.payload.payload.payload[0]
            except Exception as e:
                # print("error:"+str(cnt))
                print(e)
                pass
            datap = re.compile(r"b'[\d\w]*\\r\\n(.+?)\\r\\n")
            data = datap.findall(str(tmp))
            if data:
                try:
                    print("响应数据：" + res_dec(data[0]))
                except Exception as e:
                    # str(tmp)
                    print(e)
                    # print(data[0])
                    print("无响应")
            else:
                print("res:" + str(cnt))
                print("无响应或冰蝎默认执行")


# packets = rdpcap("./c.pcap")
# cnt = 136
# tmp = packets[cnt].payload.payload.payload.payload.payload[0]
# tmp = str(tmp)
# print(tmp)
# datap = re.compile(r"b'[\d\w]*\\r\\n(.+?)\\r\\n")
# data = datap.findall(tmp)
# print(data)

# packets = rdpcap("d.pcap")
# cc = 0
# for p in packets:
#     cnt = 0
#
#     for f in p.payload.payload.payload.payload.fields_desc:
#         if not f.name:
#             break
#         print(str(cc) + "-----------------------------------------------------")
#         # print(f.name)
#         fvalue = p.payload.getfieldval(f.name)
#         cnt = cnt + 1
#         print(str(cnt) + ". "+f.name+"：", end="")
#         print(fvalue)
#     cc = cc + 1
# c1 = 0
