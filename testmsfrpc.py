# _*_ encoding:utf-8 _*_
# __author__ = "dr0op"

from pymsfrpc import msfrpc

client = msfrpc.MsfRpcClient('msf',server='10.10.11.180')
exploit=client.modules.use('exploit','exploit/multi/handler')