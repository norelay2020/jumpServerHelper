# coding:utf-8
import logging
import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import logging
logger = logging.getLogger('django')


# 定义一个request请求的header头
def return_header():
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN',
        'Host': 'cloud.cmft.com',
        'Origin': 'https://cloud.cmft.com',
        'Content-Length': '78',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Referer': 'https://cloud.cmft.com/',
        'Connection': 'keep-alive',
        'X-Auth-Token': '[object Object]'
    }
    return headers

# 招商云模拟登录，发送验证码
def zsy_verify_code_send(username, password):
    # 招商云获取短信验证码初始登录请求url
    login_url = "https://cloud.cmft.com/api/v1/auth/login"
    # 招商云触发短信验证码发出请求url
    url_sms = "https://cloud.cmft.com/api/v1/sms/auth/sms-codes"
    # 用户名、密码
    username = username
    passwd = password
    headers = return_header()
    s = requests.session()

    # 获取用户user_id
    response = s.post(url=login_url, headers=headers, data=json.dumps({"domain": "c4933d69160a4bbaa1c17a2f0c5e1fb2", "username": username, "password": passwd, "login_system": ""}), verify=False)
    if response.status_code != 200:
        # 如果失败，返回招商云错误信息
        logger.error("请求user_id异常，疑似招商云请求接口有变动：" + json.loads(response.text)["description"])
        return json.loads(response.text)["description"]
    user_id = json.loads(response.text)["user"]["id"]
    # 触发短信验证码发送请求
    response = s.post(url=url_sms, headers=headers, data=json.dumps({"operate_type": "user_login", "user_id": user_id}), verify=False)
    if response.status_code != 200:
        # 如果失败，返回招商云错误信息
        logger.error("短信验证触发失败，user_id有误或招商云短信验证码触发请求接口有变：" + json.loads(response.text)["description"])
        return json.loads(response.text)["description"]
    logger.info("招商云短信验证触发成功，已向用户发送短信验证码。")
    return 0


# 招商云模拟登录，返回cookie
def zsy_login( username, passwd, verify_code):
    s = requests.session()
    # 招商云登录请求url
    sms_login = "https://cloud.cmft.com/api/v1/auth/sms-login"
    headers = return_header()
    response = s.post(url=sms_login, headers=headers,
                             data=json.dumps({"domain": 'c4933d69160a4bbaa1c17a2f0c5e1fb2', "username": username, "password": passwd,
                                              "sms_code": verify_code, "login_system": ""}), verify=False)
    if response.status_code != 200:
        logger.error("招商云登录请求异常：" + response.text)
        return -1
    cookie = response.cookies
    token = json.loads(response.text)['token']
    logger.info("招商云登录成功，已获取到登录成功后的token。")
    # 请求该url地址获取tenant_id, cookis需要此id才能使用
    response = s.get(url='https://cloud.cmft.com/api/v1/auth/territories?enabled=true&__limit=1000', cookies=cookie)
    if response.status_code != 200:
        logger.error("招商云登录成功，但是获取tenant_id失败，导致cooki组装失败，疑似招商云请求接口有变：" + response.text)
        return -1
    cookie = {"_a": token, "tenant_id": json.loads(response.text)["data"][0]["tenant_id"]}
    logger.info("招商云登录成功，登录后的cookie已组装完成。")
    # 转换为cookiejar格式返回
    return requests.utils.cookiejar_from_dict(cookie)


# 使用cookie爬取招商云所有主机列表信息，返回数据字典
def zsy_get_host_inf(cookies):
    # 招商云全部主机信息请求的地址
    url = 'https://cloud.cmft.com/api/v1/manage/instances?__orders=-created_date&__limit=1&__offset=0'
    # 获取招商云的cookie
    cookies = cookies
    s = requests.session()
    s.cookies = cookies
    # 获取招商云资产信息列表总条数
    response = s.get(url, verify=False)
    # 获取不到招商云资产信息列表，说明cookie超时作废了
    if not "count" in response.json().keys():
        return "401"
    logger.info("招商云主机列表信息抓取完成，总数：%s" % response.json()['count'])
    dict_t = {'count': response.json()['count'], 'data': []}
    for i in range(0, response.json()['count'] + 1, 500):
        url = 'https://cloud.cmft.com/api/v1/manage/instances?__orders=-created_date&__limit=500&__offset=%s' % i
        response = s.get(url, verify=False)
        jsonInfo = response.json()["data"]
        dict_t['data'] += jsonInfo

    # print(len(dict_t['data']))
    return dict_t


# # 建立JumpServer开源堡垒机的headers接口(API) 多因子验证
# def get_token():
#     url_login = 'https://jmsuat.cmsk1979.com/api/v1/authentication/auth/'
#     # 多因子验证url
#     url_mfa = 'https://jmsuat.cmsk1979.com/api/v1/authentication/mfa/challenge/'
#     # 用户名密码信息
#     query_args = {
#         "username": "xuwei",
#         "password": "LoxWx94?Q*c)"
#     }
#     # 首次登陆获取cookies，使用cookies请求多因子验证
#     response = requests.post(url_login, data=query_args)
#     cookie = response.cookies
#     response = requests.post(url=url_mfa, cookies=cookie,
#                              data={"code": input("多因子验证码：")})
#     # 多因子验证通过重新发起登陆请求
#     cookie = response.cookies
#     response = requests.post(url=url_login, data=query_args, cookies=cookie)
#     # 登陆完成，拿到token
#     token = json.loads(response.text)['token']
#     # print(token)
#     # 创建请求头，返回请求头
#     header_info = {"Authorization": 'Bearer ' + token}
#     return header_info


# JumpServer开源堡垒机新建资产管理接口--私有永久token，直接请求后天
# 后台生成私有永久token方法：
# source /opt/py3/bin/activate
# cd /opt/jumpserver/apps
# python manage.py shell << EOF
# from users.models import User
# u = User.objects.get(username='admin')
# u.create_private_token()
# EOF
def jump_add_host(is_test, data):
    if is_test == "True":
        # 测试环境
        url = 'https://jmsuat.cmsk1979.com/api/v1/assets/assets/'
        private_token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
    else:
        # 生产环境
        url = 'https://jms.cmsk1979.com/api/v1/assets/assets/'
        private_token = '64af818ee27a24756729c0d2977aa7b816665063'
    # 新建资产url
    header_info = {"Authorization": 'Token ' + private_token}
    # data = {
    #     'platform': 'Linux',
    #     'protocols': 'ssh/22',
    #     'nodes': '15cc50a8-c2d0-4edb-abc4-4489bce95d96',
    #     'is_active': 'true',
    #     'domain': '',
    #     'admin_user': 'd02f76d6-e8cf-4809-97f0-59d4c73e636d',
    #     'hostname': 'test_xuwei',
    #     'ip': '10.211.55.3',
    # }

    response = requests.post(url, headers=header_info, data=data, verify=False)
    # 成功返回201
    return response.status_code


# JumpServer开源堡垒机资新建节点
def jump_add_node(is_test, data):
    if is_test == "True":
        # 测试环境
        url = 'https://jmsuat.cmsk1979.com/api/v1/assets/nodes/15cc50a8-c2d0-4edb-abc4-4489bce95d96/children/'
        token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
    else:
        # 生产环境
        url = 'https://jms.cmsk1979.com/api/v1/assets/nodes/4a480585-4055-4b93-993a-865a6435a239/children/'
        token = '64af818ee27a24756729c0d2977aa7b816665063'
    header_info = {"Authorization": 'Token ' + token}
    # data = {"value": "ASK"}

    response = requests.post(url, headers=header_info, data=data)
    if json.loads(response.text)["value"] == data["value"]:
        return json.loads(response.text)["id"]
    else:
        dict_list = jump_get_node_info(is_test)
        id = [k for k, v in dict_list.items() if str(v) == data["value"]]
        return id[0]



# JumpServer开源堡垒机资产删除接口，成功返回204
def jump_delete_host(url, token):
    header_info = {"Authorization": 'Token ' + token}

    response = requests.delete(url, headers=header_info)
    return response.status_code


# 根据节点信息直接爬取JumpServer堡垒机资产信息列表，并过滤成diff_comp()可用字典返回
def jump_node_host_info(is_test, node_list):
    # 以ip为key的字典
    node_get_jump_host_dict = {}
    node_get_jump_host_set = set()
    jump_dict = []
    for node in node_list:
        data = {"value": node}
        node_key = jump_add_node(is_test, data)
        if is_test == "True":
            # 测试环境
            url = 'https://jmsuat.cmsk1979.com/api/v1/assets/assets/?node_id=%s&show_current_asset=0&offset=0&limit=100000&display=1&draw=1' % node_key
            token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
        else:
            # 生产环境
            url = 'https://jms.cmsk1979.com/api/v1/assets/assets/?node_id=%s&show_current_asset=0&offset=0&limit=100000&display=1&draw=1' % node_key
            token = '64af818ee27a24756729c0d2977aa7b816665063'
        # 获取该节点资产列表
        header_info = {"Authorization": 'Token ' + token}
        response = requests.get(url, headers=header_info)
        jump_dict += json.loads(response.text)["results"]

    #print(jump_dict) #这里有问题
    # for循环，如果node在node_list内，就加入字典和集合
    for var in jump_dict:
            tmp_dict = {}
            node_get_jump_host_set.add(str(var["ip"]))
            tmp_dict["hostname"] = str(var["hostname"])  # 主机名
            tmp_dict["hostId"] = str(var["id"])
            tmp_dict["ip"] = str(var["ip"])  # ip地址
            tmp_dict["systemType"] = str(var["platform"])  # 系统类型
            tmp_dict["node"] = str(var["nodes"])  # 节点(加密字符串)
            tmp_dict["status"] = str(var["is_active"])  # 主机状态
            tmp_dict["comment"] = str(var["comment"])  # 备注
            node_get_jump_host_dict[str(var["ip"])] = tmp_dict
    node_get_jump_host_dict["ipSet"] = node_get_jump_host_set
    return node_get_jump_host_dict


# 招商云与JumpServer开源堡垒机资产列表比对，更新JumpServer多的导入，少的删除
def diff_comp(is_test, zsy_dict, jump_dict):
    # 获取集合差异信息
    insert_set = zsy_dict["ipSet"] - jump_dict["ipSet"]   # 招商云多的
    delete_set = jump_dict["ipSet"] - zsy_dict["ipSet"]  # 堡垒机多的
    # 准备更新堡垒机环境
    for i in insert_set:
        # 判断节点
        node_data = {"value": zsy_dict[i]["node"]}
        platform = zsy_dict[i]["systemType"]
        if zsy_dict[i]["is_test"] == "True":
            # 测试环境
            if platform == "Linux":
                # 测试环境 linux 系统
                admin_user = 'd02f76d6-e8cf-4809-97f0-59d4c73e636d'
            else:
                # 测试环境 windows 系统
                admin_user = '82d38268-f271-4f5e-9dca-df0dab0d18ac'
        else:
            # 生产环境
            if platform == "Linux":
                # 生产环境 linux 系统
                admin_user = '02a00ed5-9288-41f4-a31d-081e917e952d'
            else:
                # 生产环境 windows 系统
                admin_user = '33822165-aa98-41dc-aa89-485f5c26e1f1'
        insert_data = {
            'platform': platform,
            'protocols': 'rdp/3389' if platform == "Windows" else 'ssh/22',
            'nodes': jump_add_node(zsy_dict[i]["is_test"], node_data),
            'is_active': "true" if zsy_dict[i]["status"] == "active" else "false",
            'domain': '',
            'admin_user': admin_user,
            'hostname': zsy_dict[i]["ip"] + "(" + zsy_dict[i]["netmask"] + ")",
            'ip': zsy_dict[i]["ip"],
        }
        jump_add_host(is_test, insert_data)
    logger.info("JumpServer新建完成，IP信息[%s]：%s" % (len(insert_set), insert_set))

    # 删除JumpServer多余
    for i in delete_set:
        if is_test == "True":
            # JumpServer测试环境token
            token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
            url = 'https://jmsuat.cmsk1979.com/api/v1/assets/assets/' + jump_dict[i]["hostId"] + '/'
        else:
            # JumpServer生产环境token
            token = '64af818ee27a24756729c0d2977aa7b816665063'
            url = 'https://jms.cmsk1979.com/api/v1/assets/assets/' + jump_dict[i]["hostId"] + '/'
        jump_delete_host(url, token)
    logger.info("JumpServer删除完成，IP信息[%s]：%s" % (len(delete_set), delete_set))


# 获取JumpServer的节点信息， 返回id与节点名称对应的字典
def jump_get_node_info(is_test):
    if is_test == "True":
        # JumpServer测试环境token
        token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
        url = 'https://jmsuat.cmsk1979.com/api/v1/assets/nodes/'
    else:
        # JumpServer生产环境token
        token = '64af818ee27a24756729c0d2977aa7b816665063'
        url = 'https://jms.cmsk1979.com/api/v1/assets/nodes/'

    header_info = {"Authorization": 'Token ' + token}
    dict_r = {}

    response = requests.get(url, headers=header_info)
    for i in json.loads(response.text):
        dict_r[i['id']] = i['value']
    return dict_r


# 招商云资产信息过滤返回ip为key的主机信息、ip集合、测试环境所有节点、生产环境所有节点的大字典
def zsy_filter_info(zsy_data):
    # ip集合
    zsy_set = set()
    # 测试节点列表
    test_node_list = []
    # 生产节点列表
    pro_node_list = []
    #最终大字典
    zsy_dict = {}
    for var in zsy_data:
        tmp_dict = {}
        zsy_set.add(str(var["network"]["ip"]))
        # 判断该资产为测试或者生产环境，"True" 为测试环境，False为生产环境
        is_test = "True" if str(var["az"]["name"]).find(u"测试") >= 0 else "False"
        tmp_dict["netmask"] = str(var["network"]["name"]).replace("net-cmsk", "").partition('-app')[0].partition('-db')[0].partition('-sy')[0].partition('-lb')[0].strip('-')   # 主机名
        tmp_dict["ip"] = str(var["network"]["ip"])     # ip地址
        tmp_dict["systemType"] = str(var["image"]["platform"])   # 系统类型
        tmp_dict["node"] = str(var["project"]["name"]) + "-" + str(var["project"]["name_zh"])  # 节点
        tmp_dict["status"] = str(var["vm_state"])      # 主机状态
        tmp_dict["comment"] = str(var["description"])  # 备注
        tmp_dict["area"] = str(var["az"]["name"])
        # "True" 为测试环境，False为生产环境
        tmp_dict["is_test"] = is_test
        # 获取测试和生产环境的节点列表
        if is_test == "True":
            test_node_list.append(tmp_dict["node"])
        else:
            pro_node_list.append(tmp_dict["node"])
        zsy_dict[str(var["network"]["ip"])] = tmp_dict
    zsy_dict["jihe"] = zsy_set
    zsy_dict["test_node"] = list(set(test_node_list))  # 列表去重
    zsy_dict["pro_node"] = list(set(pro_node_list))    # 列表去重
    return zsy_dict


# jump堡垒机信息过滤返回集合包含ip集合的字典
def jump_filter_info(jump_data):
    jump_set = set()
    jump_dict = {}
    for var in jump_data:
        tmp_dict = {}
        jump_set.add(str(var["ip"]))
        tmp_dict["hostname"] = str(var["hostname"])  # 主机名
        tmp_dict["hostId"] = str(var["id"])
        tmp_dict["ip"] = str(var["ip"])  # ip地址
        tmp_dict["systemType"] = str(var["platform"])  # 系统类型
        tmp_dict["node"] = str(var["nodes"])  # 节点(加密)
        tmp_dict["status"] = str(var["is_active"])  # 主机状态
        tmp_dict["comment"] = str(var["comment"])  # 备注
        tmp_dict["test"] = str(var["comment"])
        jump_dict[str(var["ip"])] = tmp_dict
    jump_dict["jihe"] = jump_set
    return jump_dict


# 根据传入节点，获取招商云对应的主机列表信息，返回以ip为Key的dict
def node_get_zsy_host_info(dict_info, is_test, node_list):
    # 以ip为key的字典
    node_get_zsy_host_dict = {}
    node_get_zsy_host_set = set()

    for key, value in dict_info.items():
        if key != "jihe" and key != "test_node" and key != "pro_node" and value["is_test"] == is_test:
            if value["node"] in node_list:
                node_get_zsy_host_dict[key] = value
                node_get_zsy_host_set.add(str(key))
    node_get_zsy_host_dict["ipSet"] = node_get_zsy_host_set
    return node_get_zsy_host_dict


# 清除JumpServer堡垒机资产
def delete_host(is_test, jump_dict):
    if is_test == "True":
        # JumpServer测试环境
        token = '045da0109f70a4023ddc6a1f69b5f15702ca59b7'
        hf = "jmsuat"
    else:
        # JumpServer生产环境
        token = '64af818ee27a24756729c0d2977aa7b816665063'
        hf = "jms"

    node_list = []
    # 删除资产
    for i in jump_dict["ipSet"]:
        url = 'https://' + hf + '.cmsk1979.com/api/v1/assets/assets/' + jump_dict[i]["hostId"] + '/'
        jump_delete_host(url, token)
        # 搜集节点信息
        node_list.append(jump_dict[i]["node"])
    # 删除节点
    for n in list(set(node_list)):
        url = 'https://' + hf + '.cmsk1979.com/api/v1/assets/nodes/' + eval(n)[0] + '/'
        jump_delete_host(url, token)

