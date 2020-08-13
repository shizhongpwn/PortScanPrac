import socket
import threading
import platform
import time
from etc import constants
class PortScan:
    __port_list_top_1000 = constants.port_list_top_1000
    __port_list_top_100 = constants.port_list_top_100
    __port_list_top_50 = constants.port_list_top_50
    __threading_num = 1000
    __delay = 10

    def __init__(self,target_ports=None):
        if target_ports is None:
            self.target_ports = self.__port_list_top_1000
        elif type(target_ports) == list:
            self.target_ports = target_ports
        elif type(target_ports) == int:
            self.target_ports = self.check_default_list(target_ports)

    def check_default_list(self,target_port_rank):
        if (
                target_port_rank != 50 and
                target_port_rank != 100 and
                target_port_rank != 1000
        ):
            raise ValueError(
                'Invalid port rank {}. Should be 50, 100 or 1,000.'.format(target_port_rank)
            )
        if target_port_rank == 50:
            return self.__port_list_top_50
        elif target_port_rank == 100:
            return self.__port_list_top_100
        else:
            return self.__port_list_top_1000


    def __usage(cls):
        print('python Port Scan v2.0')
        print('please make sure the input host name is in the form of "something.com" or "http://something.com!"\n')

    def scan(self,hostname,message=''):
        hostname = str(hostname)
        if 'http://' in hostname or 'https://' in hostname:
            hostname = hostname[hostname.find("://")+3:]
            print('*' * 60 + '\n')
            print('start scanning website: {}'.format(hostname))
        try:
            server_ip = socket.gethostbyname(hostname) # 可能无法解析出真实ip
            print('server ip is: {}'.format(str(server_ip)))
        except socket.error:
            print('hostname {} unknown!!!'.format(hostname))
            self.__usage()
            return {}
        start_time = time.time()
        output = self.__scan_ports(server_ip,self.__delay,message.encode('utf-8'))
        stop_time = time.time()
        print('host {} scanned in  {} seconds'.format(hostname, stop_time - start_time))
        print('finished scan!\n')
        return output
    def set_thread_limit(self,limit):
        limit=int(limit)
        if limit <= 0 or limit > 50000:
            print(
                'Warning: Invalid thread number limit {}!'
                'Please make sure the thread limit is within the range of (1, 50,000)!'.format(limit)
            )
            print('The scanning process will use default thread limit 1,000.')
            return
        self.__threading_num = limit
    def set_delay(self,delay):
        delay = int(delay)
        if delay <= 0 or delay > 100:
            print(
                'Warning: Invalid delay value {} seconds!'
                'Please make sure the input delay is within the range of (1, 100)'.format(delay)
            )
            print('The scanning process will use the default delay time 10 seconds.')
            return

        self.__delay = delay
    def show_target_ports(self):
        print('Current port list is:')
        print(self.target_ports)
        return self.target_ports

    def show_delay(self):
        print('Current timeout delay is {} seconds.'.format(self.__delay))
        return self.__delay

    def show_top_k_ports(self, k):
        port_list = self.check_default_list(k)
        print('Top {} commonly used ports:'.format(k))
        print(port_list)
        return port_list
    def __scan_ports_helper(self,ip,delay,output,message):
        port_idx = 0
        while port_idx<len(self.target_ports):
            while threading.activeCount()<self.__threading_num and port_idx<len(self.target_ports):
                thread = threading.Thread(target=self.__TCP_connect,args=(ip,self.target_ports[port_idx],delay,output,message))
                thread.start()
                #thread.join() #thread.join()保证了主线程只有在所有子线程都结束之后才会继续执行,但是采用多网站同时扫描的时候不可以这样
                #因为需要一个线程去管理扫描改网站的端口的其他线程
                port_idx=port_idx+1
                time.sleep(0.01)
        #while len(output) < len(self.target_ports):
        #    continue
    def __scan_ports(self,ip,delay,message):
        output = {}
        thread = threading.Thread(target=self.__scan_ports_helper, args=(ip, delay, output, message))
        thread.start()
        while len(output) < len(self.target_ports):
            time.sleep(0.01)
            continue
        for port in self.target_ports:
            if output[port] == 'OPEN':
                print('{}: {}\n'.format(port, output[port]))
            return output

    def __TCP_connect(self,ip,ports,delay,output,message):
        curr_os = platform.system() #多平台
        if curr_os == 'Windows':
            TCP_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #AF_INET IPv4 socket，SOCK_STREAM代表tcp链接的socket
            TCP_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) #socket.SOL_SOCKET代表当前socket将使用setsockopt后面的参数。
            TCP_socket.settimeout(delay)#socket.SO_REUSEPORT表明当前socket使用了可复用端口的设置,SO_REUSEADDR的意思在于避免地址冲突。
            #如果在一个socket绑定到某一地址和端口之前设置了其SO_REUSEADDR的属性，那么除非本socket与产生了尝试与另一个socket绑定到完全相同的源地址
            # 和源端口组合的冲突，否则的话这个socket就可以成功的绑定这个地址端口对。这听起来似乎和之前一样。但是其中的关键字是完全。SO_REUSEADDR
            # 主要改变了系统对待通配符IP地址冲突的方式。
        else:
            TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            TCP_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            TCP_socket.settimeout(delay)
        if message!='':
            UDP_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #udp方式
            UDP_socket.sendto(message,(ip,int(ports)))
        try:
            result = TCP_socket.connect_ex((ip,int(ports)))
            if message != '':
                TCP_socket.sendall(message)
            if result==0:
                output[ports] = 'OPEN'
            else:
                output[ports] = 'CLOSE'
            TCP_socket.close()

        except socket.error as e:
            output[ports] = 'CLOSE'
            pass

