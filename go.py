import main as ps
from etc import constants
def main():
    top_k_port = 100 # 渗透测试最常用的端口top k ，选项为 50 , 100 , 1000
    scanner = ps.PortScan(target_ports=100)
    hostname = 'baidu.com'
    message = 'put whatever message you want here'
    scanner.set_thread_limit(1000)
    scanner.set_delay(15)
    scanner.show_target_ports()
    scanner.show_delay()
    scanner.show_top_k_ports(100)
    output = scanner.scan(hostname,message)
    for key,value in output.items():
        print("port {} is {}".format(key,value))
if __name__ == '__main__':
    main()