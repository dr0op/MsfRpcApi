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
        res = self.send_command(["session.meterperter_write",self.token,ses_id,data])
        return res

    def read_meterpreter(self,ses_id):
        """
        读取meterpreter信息
        :param ses_id:
        :return:
        """
        str(ses_id)
        res = self.send_command(["session.meterperter_read",self.token,ses_id])
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

# this if statement is for testing funtions inside of auth
# only put tests here
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
