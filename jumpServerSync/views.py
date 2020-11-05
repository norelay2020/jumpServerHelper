# -*- coding: utf-8 -*-
from django.shortcuts import render, HttpResponse, redirect
from . import request_helper
import logging
import json
import  requests

# 激活日志器
logger = logging.getLogger('django')  # 此处的django为，settings.py文件中，LOGGING配置下的loggers中定义的日志器名称
logger.info("程序启动完成，日志已成功激活。")

# Create your views here.


def login_init(request):
    if request.method == "POST":
        # 获取指向/login/的ajax提交数据
        username = request.POST.get('username')
        password = request.POST.get('password')
        # print(username, password)
        # 触发招商云短信验证
        recode = request_helper.zsy_verify_code_send(username, password)
        # 返回ajax结果
        return HttpResponse(recode)


def login(request):
    if request.method == "POST":
        # 获取login页面form表单提交数据
        username = request.POST.get('uid')
        password = request.POST.get('passwd')
        verify_code = request.POST.get('vcode')
        # 登录招商云获取登录后的cookies，登录失败返回-1
        cookies = request_helper.zsy_login(username, password, verify_code)
        if cookies == -1:
            return render(request, 'login.html', {"error_msg": "获取招商云登录完成后的cookie失败，请联系管理员。"})
        # cookiejar格式转换为字典格式，并保存到session
        request.session["cookies"] = requests.utils.dict_from_cookiejar(cookies)
        # 招商云cookie组装成功，允许进入主页
        request.session["is_login"] = True
        return redirect("/index/")
    return render(request, 'login.html')


def index(request):
    # 未成功获取cookie，不允许登录
    if request.session.get("is_login") != True:
        return redirect('/login/')
    # 登录成功则取出cookie
    cookies = request.session.get('cookies')
    # session存入的cookie是字典格式，转换为cookiejar格式
    cookies = requests.utils.cookiejar_from_dict(cookies)
    # 爬取招商云全部资产信息列表，返回字典格式
    zsy_info = request_helper.zsy_get_host_inf(cookies)
    if zsy_info == "401":
        return redirect('/logout/')
    # 招商云资产信息过滤返回ip为key的主机信息、ip集合、测试环境所有节点、生产环境所有节点的大字典
    zsy_dict = request_helper.zsy_filter_info(zsy_info['data'])
    # 处理post请求
    if request.method == "POST":
        env_s = request.POST.get('env_name')
        test_s = request.POST.getlist('test_name')
        pro_s = request.POST.getlist('pro_name')
        node_list = None
        # 获取环境信息和节点信息
        if env_s == "test":
            is_test = "True"
            node_list = test_s
        elif env_s == "production":
            is_test = "False"
            node_list = pro_s
        else:
            return redirect('/logout/')
        if not node_list:
            return render(request, 'index.html', {"test": zsy_dict["test_node"], "production": zsy_dict["pro_node"]})
        # 根据全部招商云主机信息列表，过滤出环境和节点对应的主机列表信息，返回以ip为Key的字典
        zsy_dict_node = request_helper.node_get_zsy_host_info(zsy_dict, is_test, node_list)
        # 根据节点信息直接爬取JumpServer堡垒机资产信息列表，并过滤、返回以ip为Key的字典
        jump_dict_node = request_helper.jump_node_host_info(is_test, node_list)
        if request.session.get("update_way") == "all":
            # 全量更新，先删除
            request_helper.delete_host(is_test, jump_dict_node)
            jump_dict_node = {"ipSet": set()}
        # 增量更新
        # 传入招商云和JumpServer堡垒机资产信息列表的字典，更新JumpServer堡垒机对应节点资产信息
        request_helper.diff_comp(is_test, zsy_dict_node, jump_dict_node)
        # return redirect('/index/')
    # 将招商云上生产和测试的所有已存在节点信息分别返回前段页面
    return render(request, 'index.html', {"test": zsy_dict["test_node"], "production": zsy_dict["pro_node"]})


def logout(request):
    # 作废session登录状态
    request.session["is_login"] = False
    request.session["cookies"] = None
    return redirect('/login/')



# 全量更新方式则需先清除堡垒机所有主机与节点信息，该函数待补全清除功能
def update_way(request):
    # 未成功获取cookie，不允许登录
    if request.session.get("is_login") != True:
        return redirect('/login/')
    if request.method == "POST":
        # 获取指向/login/的ajax提交数据
        update_type = request.POST.get('update_way')
        if update_type:
            request.session["update_way"] = update_type
            return HttpResponse(0)
        else:
            request.session["update_way"] = None
            return HttpResponse(-1)
