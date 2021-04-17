import warnings
warnings.filterwarnings("ignore")
from requests import Session
from Crypto.Cipher import AES
import base64
import re
import time

g_username = ""  # 请填写你的账号
g_password = ""  # 请填写你的密码
g_name = ""  # 请填写你的姓名
g_idcard = ""  # 请填写你的身份证
# 暂时只能抢四级，因为作者英语太菜了没过四级，不知道六级咋报


def pkcs7padding(data):
    bs = AES.block_size
    padding = bs - len(data) % bs
    padding_text = chr(padding) * padding
    return data + padding_text


def Encrypt(word, key, iv):
    word = pkcs7padding(word).encode()
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    encrypted = cipher.encrypt(word)
    return base64.b64encode(encrypted)


def login(ss):
    loginState = False
    checkState = False
    signState = False
    rvt = ""
    sid = ""
    while not loginState:
        # 获取cookie、加密密钥、加密偏移量、
        hdnForce = ""
        hdnLoginMode = ""
        hdnReturnUrl = ""
        hdnRedirectUrl = ""
        HiddenAccessToken = ""
        key = ""
        iv = ""
        HiddenSafe = ""
        flag = True
        while flag:
            try:
                ret = ss.get(url="https://passport.neea.edu.cn/CETLogin?ReturnUrl=http://cet-bm.neea.edu.cn/Home/VerifyPassport/?LoginType=0"
                             # , proxies=proxies, verify=False
                             ).text
                rvt = re.findall(r'<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                hdnForce = re.findall(r'<input id="hdnForce" name="hdnForce" value="([0-9]+)" type="hidden" />', ret)[0]
                if ret.find(r'<input id="hdnLoginMode" name="hdnLoginMode" type="hidden" />') != -1:
                    hdnLoginMode = ""
                else:
                    hdnLoginMode = re.findall(r'<input id="hdnLoginMode" name="hdnLoginMode" value="(.+)" type="hidden" />', ret)[0]
                    print("未知状况，可能会导致功能无法使用")
                if ret.find(r'<input id="hdnRedirectUrl" name="hdnRedirectUrl" type="hidden" />') != -1:
                    hdnRedirectUrl = ""
                else:
                    hdnRedirectUrl = re.findall(r'<input id="hdnRedirectUrl" name="hdnRedirectUrl" value="(.+)" type="hidden" />', ret)[0]
                    print("未知状况，可能会导致功能无法使用")
                if ret.find(r'<input id="HiddenAccessToken" name="HiddenAccessToken" type="hidden" />') != -1:
                    HiddenAccessToken = ""
                else:
                    HiddenAccessToken = re.findall(r'<input id="HiddenAccessToken" name="HiddenAccessToken" value="(.+)" type="hidden" />', ret)[0]
                    print("未知状况，可能会导致功能无法使用")
                hdnReturnUrl = re.findall(r'<input id="hdnReturnUrl" name="hdnReturnUrl" value="(.+)" type="hidden" />', ret)[0]
                key = re.findall(r'<input id="HiddenPublicKeyExponent" value="([a-zA-Z0-9]+)" name="HiddenPublicKeyExponent" type="hidden" />', ret)[0]
                iv = re.findall(r'<input id="HiddenPublicKeyModulus" value="([a-zA-Z0-9]+)" name="HiddenPublicKeyModulus" type="hidden" />', ret)[0]
                HiddenSafe = re.findall(r'<input id="HiddenSafe" name="HiddenSafe" value="([0-9]+)" type="hidden" />', ret)[0]
            except Exception as e:
                print(e)
            else:
                flag = False
        print("成功进入到登录页面")
        # 获取验证码
        verifyImgUrl = ""
        flag = True
        while flag:
            try:
                ret = ss.post(url="https://passport.neea.edu.cn/CheckImage/LoadCheckImage"
                              # , proxies=proxies, verify=False
                              ).text
                verifyImgUrl = eval(ret)
            except Exception as e:
                print(e)
            else:
                flag = False
        print("成功获取到验证码链接", verifyImgUrl)
        verifyImg = b''
        flag = True
        while flag:
            try:
                verifyImg = ss.get(url=verifyImgUrl
                                   # , proxies=proxies, verify=False
                                   ).content
            except Exception as e:
                print(e)
            else:
                flag = False
        # print(verifyImg)
        print("成功获取到验证码")
        # 识别验证码
        verifyCode = input()
        print("成功识别出验证码", verifyCode)
        # 登录
        txtUserName = g_username
        txtPassword = Encrypt(g_password, key, iv)
        txtCheckImageValue = verifyCode
        loginDataTwice = {}
        flag = True
        while flag:
            try:
                ret = ss.post(
                    url="https://passport.neea.edu.cn/CETLogin?ReturnUrl=http://cet-bm.neea.edu.cn/Home/VerifyPassport/?LoginType=0",
                    data={
                        '__RequestVerificationToken': rvt,
                        'txtUserName': txtUserName,
                        'txtPassword': txtPassword,
                        'txtCheckImageValue': txtCheckImageValue,
                        'hdnForce': hdnForce,
                        'hdnLoginMode': hdnLoginMode,
                        'hdnReturnUrl': hdnReturnUrl,
                        'hdnRedirectUrl': hdnRedirectUrl,
                        'HiddenAccessToken': HiddenAccessToken,
                        'HiddenPublicKeyExponent': key,
                        'HiddenPublicKeyModulus': iv,
                        'HiddenSafe': HiddenSafe
                    }
                    # , proxies=proxies, verify=False
                ).text
                if ret.find("document.forms[0].submit()") != -1:
                    tmpp = re.findall(r'<input type="hidden" name="(.+)" value=[\'"]([0-9A-F]*)[\'"]>', ret)
                    for tmp in tmpp:
                        loginDataTwice[tmp[0]] = tmp[1]
                    print("成功获取到登录令牌")
                else:
                    msg = re.findall("alert\('(.+)'\);", ret)[0]
                    print(msg)
                    if msg != "验证码错误":
                        return loginState, False, False, "", ""
            except Exception as e:
                print(e)
            else:
                flag = False
        # 二次登录验证
        rvt = ""
        flag = True
        while flag:
            try:
                ret = ss.post(url="http://cet-bm.neea.edu.cn/Home/VerifyPassport/?LoginType=0",
                              data=loginDataTwice
                              # , proxies=proxies, verify=False
                              ).text
                if ret.find("欢迎登录CET考试报名系统") != -1:
                    rvt = re.findall('<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                    tmpp = re.findall('<td class="td_content">(.+)</td>', ret)
                    examName = tmpp[0]
                    if ret.find("未报名") != -1:
                        checkState = False
                        signState = False
                    elif ret.find("未报科目") != -1:
                        checkState = True
                        signState = False
                        sid = re.findall(r'\$\("#hiddenSID"\)\.val\(\'([0-9A-F]+)\'\);', ret)[0]
                    elif ret.find("已确认") != -1:
                        checkState = True
                        signState = True
                    loginState = True
                    print("成功获取到本季考试信息", examName)
            except Exception as e:
                print(e)
            else:
                flag = False
    return loginState, checkState, signState, rvt, sid


def check(ss, rvt):
    loginState = True
    checkState = False
    bindingState = False
    # 进入报名协议 & 诚信承诺书
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/DetailsAG",
                          data={'__RequestVerificationToken': rvt, 'sid': ""}
                          # , proxies=proxies, verify=False
                          ).text
            if ret.find("登　录") != -1:
                loginState = False
                return loginState, False, False, "", ""
            if ret.find("我已阅读并接受遵守本网站报名协议及诚信承诺书") != -1:
                rvt = re.findall('<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                print("成功进入到报名协议 & 诚信承诺书")
        except Exception as e:
            print(e)
        else:
            flag = False
    # 进入个人信息填写
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/DetailsQQ",
                          data={'__RequestVerificationToken': rvt, 'sign': "1"}
                          # , proxies=proxies, verify=False
                          ).text
            if ret.find("登　录") != -1:
                loginState = False
                return loginState, False, False, "", ""
            if ret.find("资格信息查询") != -1:
                rvt = re.findall('<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                print("成功进入到个人信息填写")
        except Exception as e:
            print(e)
        else:
            flag = False
    # 填写个人信息
    sid = ""
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/GetQualifications",
                          data={'IDType': "1", 'IDNumber': g_idcard, 'Name': g_name, '__RequestVerificationToken': rvt}
                          # , proxies=proxies, verify=False
                          ).json()
            # TODO
            if ret['ExceuteResultType'] == 1:
                sid = ret['Message']
                print("个人信息验证正确")
                checkState = True
            elif ret['ExceuteResultType'] == -1:
                print("个人信息验证失败", ret['Message'])
                return loginState, checkState, bindingState, "", ""
        except Exception as e:
            print(e)
        else:
            flag = False
    # 进入资格信息确认
    IDNumber = ""
    PassPortSID = ""
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/DetailsQC",
                          data={'__RequestVerificationToken': rvt, 'sid': sid}
                          # , proxies=proxies, verify=False
                          ).text
            if ret.find("登　录") != -1:
                loginState = False
                return loginState, False, False, "", ""
            if ret.find("资格信息确认") != -1:
                IDNumber = re.findall("IDNumber: '([0-9X]+)'", ret)
                PassPortSID = re.findall("PassPortSID: '([0-9A-F]+)'", ret)
                rvt = re.findall('<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                print("成功进入到资格信息确认")
        except Exception as e:
            print(e)
        else:
            flag = False
    # 确认资格信息
    sid = ""
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/AddCandidate",
                          data={'IDNumber': IDNumber, 'PassPortSID': PassPortSID, '__RequestVerificationToken': rvt}
                          # , proxies=proxies, verify=False
                          ).json()
            if ret['ExceuteResultType'] == 1:
                sid = ret['Message']
                print("资格信息确认成功")
                bindingState = True
                flag = False
            elif ret['ExceuteResultType'] == -1:
                print("资格信息确认失败", ret['Message'])
                if ret['Message'].find("报名暂未开始") == -1:
                    return loginState, checkState, bindingState, "", ""
                else:
                    time.sleep(1)
        except Exception as e:
            print(e)
        else:
            pass
    return loginState, checkState, bindingState, rvt, sid


def sign(ss, rvt, sid):
    # 进入笔试科目报考
    c_sStr = ""
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/DetailsRW",
                          data={'__RequestVerificationToken': rvt, 'sid': sid}
                          # , proxies=proxies, verify=False
                          ).text
            if ret.find("笔试科目报考") != -1:
                rvt = re.findall('<input name="__RequestVerificationToken" type="hidden" value="([a-zA-Z0-9_-]+)" />', ret)[0]
                c_sStr = re.findall('<input id="([0-9_]+)" name="ckbSubject" disabled class="md-check" type="checkbox">', ret)
                if len(c_sStr) == 1:
                    c_sStr = c_sStr[0]
                else:
                    print("啥情况啊，咋不止一个科目能报啊")
                    return False
                print("成功进入到笔试科目报考")
                volState = re.findall(r'<!-- 剩余容量-->\s+<td align="center">\s+(.+)\s+</td>', ret)[0]
                if volState.find("无") != -1:
                    print("名额已被抢完")
                    return False
        except Exception as e:
            print(e)
        else:
            flag = False
    # 提交报考
    flag = True
    while flag:
        try:
            ret = ss.post(url="http://cet-bm.neea.edu.cn/Student/SaveRW",
                          data={'__RequestVerificationToken': rvt, 'sid': sid, 'c_sStr': c_sStr}
                          # , proxies=proxies, verify=False
                          ).json
            if ret['ExceuteResultType'] == 1:
                print("提交报考成功")
                return True
            elif ret['ExceuteResultType'] == -1:
                print("提交报考失败", ret['Message'])
                return False
        except Exception as e:
            print(e)
        else:
            flag = False


def main():
    ss = Session()
    needLogin = True
    while needLogin:
        rst = login(ss)
        if not rst[0]:  # 账号或密码错误
            return
        needLogin = False
        if rst[2]:  # 已报名
            print("您似乎已经完成了报名，祝您考试顺利哦！")
            return
        if not rst[1]:  # 未填写个人信息
            rst = check(ss, rst[3])
            if not rst[0]:
                needLogin = True
                continue
            if not rst[1]:  # 姓名或身份证错误
                return
            if not rst[2]:  # 资格确认失败
                return
        rst = sign(ss, rst[3], rst[4])
        if rst:
            print("大概报名成功了，记得在24小时内错峰支付哦，祝您考试顺利哦！")
        else:
            print("好像没机会了，下次再来抢吧...")
        break


if __name__ == '__main__':
    # proxies = {'http': "http://127.0.0.1:10801", 'https': "http://127.0.0.1:10801"}
    main()
