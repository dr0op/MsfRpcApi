# Metasploit API使用文档

Metasploit官方提供了API调用方式，有

* RPC
* REST

两种API调用方式，REST方式只支持专业版使用，这里推荐使用RPC方式调用，即标准API调用。

## 使用RPC API调用

在通过对Cobalt Strike2.4版本客户端和`armitage`客户端进行反编译，发现其API调用也为RPC调用。可以认为RPC API调用是"稳定"，“可靠”的。

### RPC API 调用官方文档

https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

## 开启服务端RPC 服务

开启服务端API服务有两种方式：

1. 通过msfconsole加载msfrpc插件来开启RPC
2. 通过msfrpcd服务来开启RPC

`msfconsole`其实也可以理解为`metasploit`的`客户端`,和`msfclient`,`armitage`的功能一致。只是操作方式有所不同。

### 通过msfconsole加载RPC

进入`msfconsole`之后，运行加载命令

```shell
msf5 > load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User='msf' Pass='msf'
[*] MSGRPC Service:  127.0.0.1:55553
[*] MSGRPC Username: msf
[*] MSGRPC Password: msf
[*] Successfully loaded plugin: msgrpc
msf5 >
```

其中Serverhost即运行msf的主机，可以为`127.0.0.1`也可以是`0.0.0.0`区别是前者只能本机连接。

### 通过msfrpcd来开启RPC服务

```shell
$ msfrpcd -U msf -P msf -S -f                                                                                                    
[*] MSGRPC starting on 0.0.0.0:55553 (NO SSL):Msg...
[*] MSGRPC ready at 2018-10-17 11:06:46 +0800.
```

即以用户名和密码分别为`msf`，`msf`，不启用`SSL`来开启服务。`msfrpcd`和`msfconsole`命令一般在同一目录下。如果环境变量设置正确，一般可以直接使用。

关于msfrpcd的详细参数如下：

```shell
$ ./msfrpcd -h

   Usage: msfrpcd <options>

   OPTIONS:

       -P <opt>  设置RPC登录密码
       -S        在RPC socket上禁止使用SSL
       -U <opt>  设置RPC登录用户名
       -a <opt>  绑定一个IP地址（本机IP地址）
       -f        在后台以精灵进程（守护进程）的方式运行、启动
       -h        帮助菜单
       -n        禁止使用数据库
       -p <opt>  绑定某个端口，默认为55553
       -u <opt>  设置Web服务器的URI
```

## MSF RPC 与msgpack

与msf rpc api通信需要对通信的内容使用`msgpack`进行序列化，简单来说就是将要发送的数据包转换为二进制形式，以便于传输和格式统一。msgpack序列化之后的数据包支持多种语言，可以在msf服务端由ruby正常解析。

Python下安装msgpack包：

```shell
$ pip install msgpack
```

```python
>>> import msgpack
>>> dic = {'result': 'success', 'token': 'TEMPSsU2eYsNDom7GMj42ZldrAtQ1vGK'}
>>> res = msgpack.packb(dic)
>>> res
'\x82\xa5token\xda\x00 TEMPSsU2eYsNDom7GMj42ZldrAtQ1vGK\xa6result\xa7success'
>>>

```

## MSF API请求

在服务端开启RPC之后，可以使用HTTP协议去访问,会提示404，访问'api'会将文件下载下来。如果发生上述效果，表明服务端开启成功。

其实，MSF的RPC调用也利用HTTP协议，需要先连接`RPC socket`然后构造`POST`请求，不同的是，需要指定`Content-type`为`binary/message-pack`，这样客户端才会正确解析包。

### 登录认证API调用

登录认证时向服务端`POST`序列化发送如下数据包:

成功的请求示例

客户：

```json
[ "auth.login", "MyUserName", "MyPassword"]
```

服务器：

```json
{ "result" => "success", "token" => "a1a1a1a1a1a…" }
```

这里用一个连接`MSF`服务端并进行登录的简单demo来演示：

```python

# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"
# python3

import msgpack
import http.client

HOST="127.0.0.1"
PORT="55553"
headers = {"Content-type" : "binary/message-pack"}

# 连接MSF RPC Socket
req = http.client.HTTPConnection(HOST, PORT)
options = ["auth.login","msf","msf"]
# 对参数进行序列化（编码）
options = msgpack.packb(options)
# 发送请求，序列化之后的数据包
req.request("POST","/api/1.0",body=options,headers=headers)
# 获取返回
res = req.getresponse().read()
# 对返回进行反序列户（解码）
res = msgpack.unpackb(res)
res = res[b'token'].decode()
print(res)
```

成功执行的结果`res`如下：

```json
{'result': 'success', 'token': 'TEMPSsU2eYsNDom7GMj42ZldrAtQ1vGK'}
```

`Token`是一个随机字符串，是登录认证后的标识。

## API详解

以上使用一个简单的例子理解请求的`API`调用数据包格式及请求方式，其他的`API`请求都是同理的。只是请求的内容有所改变而已。

关于常用的API请求和返回总结如下：

#### 认证：

成功的请求示例

客户：

```json
[ "auth.login", "MyUserName", "MyPassword"]
```

服务器：

```json
{ "result" => "success", "token" => "a1a1a1a1a1a…" }
```

### 不成功的请求示例

客户：

```json
[ "auth.login", "MyUserName", "BadPassword"]
```

服务器：

```json
{
"error" => true,
"error_class" => "Msf::RPC::Exception",
"error_message" => "Invalid User ID or Password"
} 
```

退出同理



## console.create 创建一个终端

在成功登录之后，就可以使用console.create创建一个终端实例。创建过程需要一定的时间，如果上个创建未完成，下一终端创建返回的dict会提示`busy`项为`True`

客户：

```json
[ "console.create", "<token>"]
```

服务器：

```json
{
"id" => "0",
"prompt" => "msf > ",
"busy" => false
}
```

## console.destroy删除一个终端

客户：

```json
[ "console.destroy", "<token>", "ConsoleID"]
```

服务器：

```json
{ "result" => "success" }
```

## console.list

console.list方法将返回所有现有控制台ID，其状态和提示的哈希值。

客户：

```json
[ "console.list", "<token>"]
```

服务器：

```jsno
{
"0" => {
  "id" => "0",
  "prompt" => "msf exploit(\x01\x02\x01\x02handler\x01\x02) > ",
  "busy" => false
  },
"1" => {
  "id" => "1",
  "prompt" => "msf > ",
  "busy" => true
  }
}
```

## console.write

console.write方法将数据发送到创建的终端，就想平时操作msfconsole那样，但需要给不同的命令后加上换行。

客户：

```json
[ "console.write", "<token>", "0", "version\n"]
```

服务器：

```json
{ "wrote" => 8 }
```

##  

## console.read

console.read方法将返回发送到终端命令的执行结果。

客户：

```json
[ "console.read", "<token>", "0"]
```

服务器：

```json
{
"data" => "Framework: 4.0.0-release.14644[..]\n",
"prompt" => "msf > ",
"busy" => false
}
```

## MsfRpcClient

再使用一个`MSF RPC` Demo来演示一下：

```python
# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"
# python3
import msgpack
import time
import http.client

HOST="127.0.0.1"
PORT="55553"

class Msfrpc:
    
    class MsfError(Exception):
		"""
		异常处理函数
		"""
        def __init__(self, msg):
            self.msg = msg
        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        """
        登录异常处理
        """
        def __init__(self, msg):
            self.msg = msg

    def __init__(self, opts=[]):
        self.host = HOST
        self.port = PORT
        self.uri = "/api"
        self.ssl = False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type" : "binary/message-pack"}
        if self.ssl:
            self.cli = http.client.HTTPConnection(self.host,self.port)
        else:
            self.cli = http.client.HTTPConnection(self.host, self.port)

    def encode(self, data):
        """
        序列化数据(编码)
        """
        return msgpack.packb(data)

    def decode(self, data):
        """
        反序列化数据（解码）
        """
        return msgpack.unpackb(data)

    def call(self, meth, opts = []):
        if meth != "auth.login":
            if not self.authenticated:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")
        if meth != "auth.login":
            opts.insert(0,self.token)

        opts.insert(0,meth)
        params = self.encode(opts)
        # 发送请求包
        res = requests.post(self.uri, params,self.headers)
        resp = self.cli.getresponse()
		# 获取结果并解码
        return self.decode(resp.read())

    def login(self, user, password):
        """
        登录认证函数
        """
        ret = self.call('auth.login', [user,password])
        if ret.get('result') == 'success':
            self.authenticated = True
            self.token = ret.get('token')
            return True

        else:
            raise self.MsfAuthError("MsfRPC: Authentication failed")


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
    # 要发送给终端的命令
    cmd = """
 		 use auxiliary/scanner/ssh/ssh_login

         set RHOSTS 127.0.0.1
        
         set USERNAME root
         
         set PASS_FILE /tmp/pass.txt
        
         exploit

        """
    client.call('console.write',[console_id,cmd])
    time.sleep(1)
    while True:
        # 发送命令并获取结果
        res = client.call('console.read',[console_id])
        if len(res['data']) > 1:
                print (res['data'])
        if res['busy'] == True:
                time.sleep(1)
                continue
        break

    client.call('console.destroy',[console_id])

```

在这个例子中，调用MSF RPC登录获取`Token`之后，创建一个`console`，并发送命令到`console，由msf服务端去执行。执行成功之后会将结果以序列化后的形式返回。反序列化之后成为一个dict，包含了返回后的结果。

## 对API进行封装

以上是一个基础的MSF API简单调用模块去攻击的demo，但是在应用中，需要对其常见的API调用进行封装，做成一个属于我们自己的`库`，使用时，只需要去调用它即可。

简单的封装如下：

```python
import msgpack
import http.client as request


class AuthError(Exception):
    """
    登录认证错误异常处理
    """
    def __init__(self):
        print("登录失败，检查账户密码")



class ConnectionError(Exception):
    """
    链接msfrpc错误异常处理
    """
    def __init__(self):
        print("连接失败，服务端或网络问题")


class Client(object):
    """
    MsfRPC Client客户端，发送处理命令行参数
    """
    def __init__(self,ip,port,user,passwd):
        # 属性
        self.user = user
        self.passwd = passwd
        self.server = ip
        self.port = port
        self.headers = {"Content-Type": "binary/message-pack"}
        self.client = request.HTTPConnection(self.server,self.port)
        self.auth()


    #装饰器对属性读写前的处理
    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self,value):
        self._headers = value

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self,value):
        #将数据打包为通用模式
        self._options = msgpack.packb(value)

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self,value):
        self._token = value

    def auth(self):
        """
        登录认证函数
        :return 一串随机的token值:
        """
        print("Attempting to access token")
        self.options = ["auth.login",self.user,self.passwd]
        try:
            self.client.request("POST","/api",body=self.options,headers=self.headers)
        except:
            ConnectionError()
        c = self.client.getresponse()
        if c.status != 200:
           raise ConnectionError()
        else:
            res = msgpack.unpackb(c.read())
            print(res)
            if b'error' not in res.keys() and res[b'result'] == b'success':
                self.token = res[b'token']
                print("Token recived:> %s",self.token)
            else:
                raise AuthError()

    def send_command(self,options):
        self.options = options
        self.client.request("POST","/api",body=self.options,headers=self.headers)
        c = self.client.getresponse()
        if c.status != 200:
            raise ConnectionError()
        else:
            res = msgpack.unpackb(c.read())
            return res


    def get_version(self):
        """
        获取msf和ruby的版本信息
        :return ruby 和 msf vresion:
        """
        res = self.send_command(["core.version",self.token])
        return res

    def create_console(self):
        """
        创建一个虚拟终端
        :return :
        """
        res = self.send_command(["console.create",self.token])
        return res

    def destroy_console(self,console_id):
        """
        销毁一个终端
        :param console_id 终端id:
        :return:
        """
        #console_id = str(console_id)
        res = self.send_command(["console.destroy",self.token,console_id])
        return res

    def list_consoles(self):
        """
        获取一个已获取的终端列表，【id,prompt,busy】
        :return list[id,prompt,busy]:
        """
        res = self.send_command(["console.list",self.token])
        return res

    def write_console(self,console_id,data,process=True):
        """
        向终端中写命令
        :param console_id: id
        :param data:要发送到终端的命令
        :param process:
        :return:
        """
        if process == True:
            data +="\n"
        str(console_id)
        res = self.send_command(["console.write",self.token,console_id,data])
        return res

    def read_console(self,console_id):
        """
        获取发送命令后终端的执行结果
        :param console_id:
        :return:
        """
        str(console_id)
        res = self.send_command(["console.read",self.token,console_id])
        return res

    def list_sessions(self):
        """
        列出所有session信息
        :return:
        """
        res = self.send_command(["session.list",self.token])
        return res

    def stop_session(self,ses_id):
        """
        停止一个session
        :param ses_id:
        :return:
        """
        str(ses_id)
        res = self.send_command(["session.stop",self.token,ses_id])
        return res

    def read_shell(self,ses_id,read_ptr=0):
        """
        获取session执行shell信息
        :param ses_id:
        :param read_ptr:
        :return:
        """
        str(ses_id)
        res = self.send_command(["session.shell_read",self.token,ses_id,read_ptr])
        return res

    def write_shell(self,ses_id,data,process=True):
        """
        向一个shell发送命令
        :param ses_id:
        :param data:
        :param process:
        :return:
        """
        if process == True:
            data += "\n"
        str(ses_id)
        res = self.send_command(["session.shell_write",self.token,ses_id,data])
        return res

    def write_meterpreter(self,ses_id,data):
        """
        向meterpreter发送命令
        :param ses_id:
        :param data:
        :return:
        """
        str(ses_id)
        res = self.send_command(["session.meterpreter_write",self.token,ses_id,data])
        return res

    def read_meterpreter(self,ses_id):
        """
        读取meterpreter信息
        :param ses_id:
        :return:
        """
        str(ses_id)
        res = self.send_command(["session.meterpreter_read",self.token,ses_id])
        return res

    def run_module(self,_type,name,HOST,PORT,payload=False):
        """
        执行模块
        :param _type:
        :param name:
        :param HOST:
        :param PORT:
        :param payload:
        :return:
        """
        if payload != False:
            d = ["module.execute",self.token,_type,name,{"LHOST":HOST,"LPOST":PORT}]
        else:
            d = ["module.execute",self.token,_type,name,{"RHOST":HOST,"RHOST":PORT}]
        res = self.send_command(d)
        return res


# if __name__ == "__main__":
#     auth = Client("127.0.0.1","msf","yFdkc6fB")
#     print(auth.get_version())
#     print(auth.list_consoles())
#     print(auth.create_console())
#     print(auth.read_console(1))
#     print(auth.write_console(1,"ls"))
#     print(auth.destroy_console(1))
#     print(auth.list_sessions())
#     print(auth.run_module("exploit","ms17_010_eternalblue","1.1.1.1","1"))

```

使用这个库去调用攻击模块：

```python
# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"

from pymsfrpc import msfrpc
import time

ip = "10.10.11.180"
port = "55553"
user = "msf"
passwd = "msf"
c = msfrpc.Client(ip,port,user,passwd)

console_id = c.create_console().get(b'id')
cmd = """
         use auxiliary/scanner/ssh/ssh_login

         set RHOSTS 127.0.0.1
        
         set USERNAME root
         
         set PASS_FILE /tmp/pass.txt
        
         exploit
      """
res = c.get_version()
resp = c.write_console(console_id,cmd)
time.sleep(1)
while True:
    res = c.read_console(console_id)
    if res[b'busy'] == True:
        time.sleep(1)
        continue
    elif res[b'busy'] == False:
        print(res[b'data'].decode())
        break
c.destroy_console(console_id)
```

以上封装改自github开源代码msf-autopwn

https://github.com/DanMcInerney/msf-autopwn

有所改动。

## 更全面的封装

更全面的封装可参考

https://github.com/isaudits/msfrpc_console/blob/master/modules/pymetasploit/src/metasploit/msfrpc.py

要在较成熟系统上使用可参考，使用GPL0.4开源协议。

## 存在的问题及解决方案

#### 1. 反序列化后的格式问题

在`Python3`版本测试过程中，发现对返回数据进行反序列化之后，出现类似：

```
{b'result': b'success', b'token': b'TEMPEqU3buWpncDeoBryIWOgKJ9O34cJ'}
```

这种格式的dict，这表示dict的内容即keys和values是`bytes`类型的。这给我们的后续操作带来很大的不便，在判断时需要将其转化为`str`类型。要转化，只需要将其项`decode（）`即可。然而，dict并不支持decode，需要遍历其中的项并进行转化。

转换方法现提供如下：

```Python
def convert(data):
    """
    对Bytes类型的dict进行转化，转化为项为Str类型
    """
    if isinstance(data, bytes):  return data.decode('ascii')
    if isinstance(data, dict):   return dict(map(convert, data.items()))
    if isinstance(data, tuple):  return map(convert, data)
    return data

```

#### 2. ~~meterpreter无法获取session问题~~

> demo代码中meterpreter单词拼写错误导致

~~使用`msfvenom`生成一个木马并在目标执行。在msf服务端使用MSF RPC进行监听。使用`session.list`成功获取session列表。返回结果如下：~~

```json
{14: {b'type': b'meterpreter', b'tunnel_local': b'10.10.11.180:3355', b'tunnel_peer': b'10.10.11.180:55656', b'via_exploit': b'exploit/multi/handler', b'via_payload': b'payload/windows/meterpreter/reverse_tcp', b'desc': b'Meterpreter', b'info': b'LAPTOP-0IG64IBE\\dr0op @ LAPTOP-0IG64IBE', b'workspace': b'false', b'session_host': b'10.10.11.180', b'session_port': 55656, b'target_host': b'10.10.11.180', b'username': b'dr0op', b'uuid': b'j3oe1mtk', b'exploit_uuid': b'nxyfbzx4', b'routes': b'', b'arch': b'x86', b'platform': b'windows'}}
```

~~session ID为14。~~

~~成功获取session列表后，就可以向session读写meterpreter命令。~~

```python
c.write_meterpreter(14,'getuid\n')
```

```
c.read_meterpreter(14)
```

~~然而，MSF RPC端返回如下：~~

```json
write meterpreter {b'error': True, b'error_class': b'ArgumentError', b'error_string': b'Unknown API Call: \'"rpc_meterperter_write"\'', b'error_backtrace': [b"lib/msf/core/rpc/v10/service.rb:143:in `process'", b"lib/msf/core/rpc/v10/service.rb:91:in `on_request_uri'", b"lib/msf/core/rpc/v10/service.rb:72:in `block in start'", b"lib/rex/proto/http/handler/proc.rb:38:in `on_request'", b"lib/rex/proto/http/server.rb:368:in `dispatch_request'", b"lib/rex/proto/http/server.rb:302:in `on_client_data'", b"lib/rex/proto/http/server.rb:161:in `block in start'", b"lib/rex/io/stream_server.rb:48:in `on_client_data'", b"lib/rex/io/stream_server.rb:199:in `block in monitor_clients'", b"lib/rex/io/stream_server.rb:197:in `each'", b"lib/rex/io/stream_server.rb:197:in `monitor_clients'", b"lib/rex/io/stream_server.rb:73:in `block in start'", b"lib/rex/thread_factory.rb:22:in `block in spawn'", b"lib/msf/core/thread_manager.rb:100:in `block in spawn'"], b'error_message': b'Unknown API Call: \'"rpc_meterperter_write"\''}

```

```python
read meterpreter {b'error': True, b'error_class': b'ArgumentError', b'error_string': b'Unknown API Call: \'"rpc_meterperter_read"\'', b'error_backtrace': [b"lib/msf/core/rpc/v10/service.rb:143:in `process'", b"lib/msf/core/rpc/v10/service.rb:91:in `on_request_uri'", b"lib/msf/core/rpc/v10/service.rb:72:in `block in start'", b"lib/rex/proto/http/handler/proc.rb:38:in `on_request'", b"lib/rex/proto/http/server.rb:368:in `dispatch_request'", b"lib/rex/proto/http/server.rb:302:in `on_client_data'", b"lib/rex/proto/http/server.rb:161:in `block in start'", b"lib/rex/io/stream_server.rb:48:in `on_client_data'", b"lib/rex/io/stream_server.rb:199:in `block in monitor_clients'", b"lib/rex/io/stream_server.rb:197:in `each'", b"lib/rex/io/stream_server.rb:197:in `monitor_clients'", b"lib/rex/io/stream_server.rb:73:in `block in start'", b"lib/rex/thread_factory.rb:22:in `block in spawn'", b"lib/msf/core/thread_manager.rb:100:in `block in spawn'"], b'error_message': b'Unknown API Call: \'"rpc_meterperter_read"\''}
```

~~暂未找到解决方案。~~

# 总结

该文档由浅入深地描述了MSF API调用开发的方式及常见问题。并且由于每个人的环境不同，相同的代码在不同的环境中可能无法运行，需自行解决环境及依赖问题。封装方法精力允许的情况下推荐第二种封装方式。更为专业及具有可扩展性。
