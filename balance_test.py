import random
import time
import numpy as np
import dns.resolver
import matplotlib.pyplot as plt


def query_loop(domain_name, nameserver_plan):
    # nameserver = [['116.57.77.221'], ['116.57.77.220'], ['116.57.77.219'], ['116.57.77.218'], ['116.57.77.217']]
    nameserver = [['8.8.8.8'], ['8.8.8.8'], ['8.8.8.8'], ['202.38.193.33'], ['202.38.193.33']]
    self_server = dns.resolver.Resolver()       # 自定义DNS服务
    full_back = []                              # 声明全响应变量
    for i in range(len(nameserver_plan)):       # 循环通过不同服务器解析请求
        back = []
        # print("正在请求服务器:", nameserver[nameserver_plan[i]])
        self_server.nameservers = nameserver[nameserver_plan[i]]
        A = self_server.resolve(domain_name, "A")
        for j in A.response.answer:             # 将A记录提取出来
            for k in j.items:
                back.append(k.address)
        back.sort()                             # 整理本次返回值，方便裁决
        full_back.append(back)                  # 将本次返回值加入全响应
    return full_back


def ruling(full_back, ruling_weight):           # 根据输出结果和裁决权重确定好坏结果，
    global plan                                 # 声明全局变量：当前调度方案
    results = []                                # 声明裁决结果变量
    Max = 0                                     # 初始化最高裁决权重
    for i in range(len(full_back)):
        weight = 0                              # 初始化本轮裁决权重
        good_result = []                        # 初始化本轮好结果
        bad_result = []                         # 初始化本轮坏结果
        good_result_link = []                   # 初始化本轮好结果索引
        for j in range(len(full_back)):
            if full_back[i] == full_back[j]:    # 以该结果为基准对比所有结果
                weight += ruling_weight[j]      # 以该方案为基准的裁决权重
                good_result.append(plan[j])     # 以该方案为基准的好结果
                good_result_link.append(j)
            else:
                bad_result.append(plan[j])      # 以该方案为基准的坏结果
        if weight > Max:                        # 裁决权重大于最高裁决权重则该方案胜出
            Max = weight                        # 更新最高裁决权重
            results = [good_result, bad_result, good_result_link]   # 更新裁决结果
    return results


def update(results):                            # 更新参数
    global reliability                          # 声明一些全局参数
    global all_run_time
    global run_time
    global set_time
    if len(results[1]) == 0:                        # 未被攻击情况
        # set_time += 0.1                             # 对调度时间阈值进行调整
        for i in range(len(results[0])):
            all_run_time[results[0][i]] += 1        # 对在线执行体进行在线时间更新
            if reliability[results[0][i]] < 2:      # 对执行体安全度进行调整
                reliability[results[0][i]] += 0.1
    else:                                           # 受到攻击情况
        set_time = set_time/2                       # 调度时间阈值降为原来的一半
        for j in range(len(results[0])):            # 多模判决优势方，可信度降半处理
            all_run_time[results[0][j]] += 1
            reliability[results[0][j]] = reliability[results[0][j]]/2
        for k in range(len(results[1])):            # 多模判决劣势方，可信度降为1/4
            all_run_time[results[1][k]] += 1
            reliability[results[1][k]] = reliability[results[1][k]]/4
    return 0


def seed_growth(random_seed, server_num):       # 根据已有种子选取调度方案
    global He_degree                            # 声明一些全局参数
    global reliability
    global performance
    global all_run_time
    global whole_time
    Q_value = []                    # 初始化Q值数组
    leaf_num = server_num - 1       # 确定要剩余要选取的执行体数
    whole = [random_seed]           # 初始化调度方案
    for i in range(5):              # 计算Q值
        Q_value.append(0.3*He_degree[random_seed][i] + 0.7*reliability[i] + 0.3*performance[i]
                        - 0.3*all_run_time[i]/whole_time + random.uniform(-0.05, 0.05))
    # print("Q值:", Q_value)
    Q_value_p1 = np.array(Q_value)          # 备用numpy数组
    Q_value_p1[random_seed] = 0             # 剔除已选种子
    Q_value_p2 = abs(np.sort(-Q_value_p1))  # 按Q值从大到小排序，备用numpy数组
    for j in range(leaf_num):               # 选取剩余执行体
        num = len(np.where(Q_value_p1 == Q_value_p2[j])[0])         # 得到同等优先级执行体个数
        whole_plan = np.where(Q_value_p1 == Q_value_p2[j])[0]       # 保存方案
        if num == 1:                                                # 同Q值仅一个执行体，则直接选择
            whole.append(whole_plan[0])
            Q_value_p1[whole_plan[0]] = 0                           # 抹零，避免再次选中
        else:
            random_choice = np.random.choice(whole_plan, size=1)    # 同Q值多个执行体，则随机选一个
            whole.append(random_choice[0])
            Q_value_p1[random_choice[0]] = 0                        # 抹零，避免再次选中
    return whole


def scheduler(old_plan, results):       # 调度执行函数，决定下一轮组合
    global set_time                     # 声明一些参数
    global run_time
    global whole_time
    if len(old_plan) == 0:              # 系统开机，初始方案随机决定
        server_num = random.randint(3, 4)
        # server_num = 3
        server_plan = random.sample(range(0, 5), server_num)
        set_time = 10
    elif len(results[1]) != 0 or run_time >= set_time:  # 出现被攻击情况或达到调度时间阈值
        run_time = 0                                    # 运行时间清零
        server_num = random.randint(3, 4)               # 随机决定冗余度
        # server_num = 3
        find_threshold = reliability
        find_threshold.sort()                           # 找到执行体池中可信度的中位数，作为可信度阈值
        random_seed = random.randint(0, 4)              # 随机种子
        while reliability[random_seed] < 1: #find_threshold[2]:     # 可信度低于阈值的种子舍弃
            random_seed = random.randint(0, 4)
        server_plan = seed_growth(random_seed, server_num)      # 根据种子确定调度方案
    else:
        server_plan = old_plan                          # 无必要不进行调度
    return server_plan


if __name__ == '__main__':
    He_degree = [[0, 0.52, 0.4, 0.88, 0.76], [0.52, 0, 0.52, 1, 0.88], [0.4, 0.52, 0, 0.88, 0.76],
                 [0.88, 1, 0.88, 0, 0.52], [0.76, 0.88, 0.76, 0.52, 0]]   # 先验异构度矩阵
    reliability = [1, 1, 1, 1, 1]       # 可信度
    performance = [0.97, 1, 0.6, 0.9, 0.84]       # 性能评分
    all_run_time = [0, 0, 0, 0, 0]      # 各服务器解析次数
    ruling_weights = [1, 1, 1, 1, 1]    # 裁决权重（仅测试用，需动态更新）
    plan = []                           # 初始化调度方案
    result = []                         # 初始化解析结果
    run_time = 0                        # 初始化本轮调度方案解析次数
    set_time = 0                        # 初始化调度时间阈值
    whole_time = 0                      # 初始化系统总解析次数
    on = 'y'                            # 运行标志
    # while on == 'y':
    while whole_time <= 999:
        plan = scheduler(plan, result)                      # 调度程序
        print("当前调度方案为:", plan)
        # domain_name_m = input("请输入网址:")
        domain_name_m = 'baidu.com'
        full_back_m = query_loop(domain_name_m, plan)       # 解析请求
        if full_back_m:
            # print("全部响应:", full_back_m)
            result = ruling(full_back_m, ruling_weights)    # 多模裁决
            # print("判决结果:", result)
            if result[1]:
                print("####### 疑似受到攻击!!! #######")
            # print("解析结果为:", full_back_m[result[2][0]])
            run_time += 1
            # print(run_time, set_time)
            whole_time += 1
            update(result)                                  # 更新参数
            # print("可信度:", reliability)
            # print("各服务器解析次数:", all_run_time)
        else:
            print("解析错误")
        # on = input("是否继续？（y/n):")
    x = np.arange(5)
    y = np.array(all_run_time)
    plt.bar(x, y, tick_label=['Bind9', 'Powerdns', 'dnspod', 'unbound', 'maradns'], width=0.3, label='run time')
    plt.legend()
    plt.show()