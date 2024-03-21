import time
import dns.resolver


def test_pre():
    # nameserver = ['116.57.77.221', '116.57.77.220', '116.57.77.219', '116.57.77.218', '116.57.77.217']
    nameserver = [['8.8.8.8'], ['202.38.193.33'], ['114.114.114.114'], ['202.38.193.33'], ['202.38.193.33']]
    test_web = ['baidu.com', 'huya.com', 'bilibili.com', 'jd.com', 'scut.edu.cn', 'csdn.net', 'github.com',
                'people.com.cn', 'iqiyi.com', 'youku.com']
    pre = []
    self_server = dns.resolver.Resolver()
    for i in range(len(nameserver)):
        print("正在测试第", i + 1, "个服务器")
        start = time.time()
        self_server.nameservers = nameserver[i]
        for j in range(10):
            for k in range(len(test_web)):
                A = self_server.resolve(test_web[k], "A")
            print("已完成", j + 1, "轮测试")
        end = time.time()
        pre.append(end - start)
    return pre


if __name__ == '__main__':
    preform = test_pre()
    print(preform)
