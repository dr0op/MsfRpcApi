# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"

import msgpack
import http.client

HOST="10.10.11.180"
PORT="55553"
headers = {"Content-type" : "binary/message-pack"}

req = http.client.HTTPConnection(HOST, PORT)
options = ["auth.login","msf","msf"]
options = msgpack.packb(options)
req.request("POST","/api/1.0",body=options,headers=headers)
res = req.getresponse().read()
res = msgpack.unpackb(res)
res = res[b'token'].decode()
print(res)