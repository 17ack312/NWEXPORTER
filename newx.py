import os, sys, subprocess, ctypes, tempfile, shutil, datetime
import style, requests, urllib3
import nmap

nm = nmap.PortScanner()

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
master={}
path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'
path='C:/Users/Rajdeep Basu/Desktop/UGC/'
mod = path + 'module/'
out = mod.replace('module', 'out')

def _crdir(path):
    try:
        os.mkdir(path)
    except:
        pass

def _rmdir(path):
    if (os.path.exists(path)):
        shutil.rmtree(path)

def _scan(ip, arg):
    res = nm.scan(hosts=ip, arguments=arg)['scan']
    for i in res.keys():
        res = res[i]
    return res

_crdir(path)
_crdir(mod)
_crdir(out)
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


def get_status(host):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        res = requests.get(host, verify=False).status_code
    except:
        res = 0
    return res

def get_url(hostname, ip):
    urls = []
    if get_status('https://' + ip + '/') == 200:
        urls.append('https://' + ip + '/')
    elif get_status('http://' + ip + '/') == 200:
        urls.append('http://' + ip + '/')
    else:
        for i in hostname:
            if get_status('https://' + i + '/') == 200:
                urls.append('https://' + i + '/')
            elif get_status('http://' + i + '/') == 200:
                urls.append('http://' + i + '/')
    return urls


def check_ip(host):
    data = {}
    x = str(host.removeprefix('https://').removeprefix('http://').removeprefix('HTTPS://').removeprefix(
        'HTTP://').removeprefix('www.').removeprefix('WWW.').split('/')[0])
    res = nm.scan(hosts=x, arguments='-sn')['scan']
    for i in res.keys():
        res = (res[i])
    hostnames = []
    if str(res['status']['state']).lower() == 'up':
        for i in res['hostnames']:
            hostnames.append(i['name'])
        ip_add = str(res['addresses']['ipv4'])
        try:
            mac_add = str(res['addresses']['mac'])
        except:
            mac_add = None
        urls = get_url(hostnames, ip_add)

    data['ip'] = str(ip_add)
    data['mac'] = str(mac_add)
    data['hostnames'] = list(hostnames)
    data['url'] = list(urls)

    return data,x



def hosts_input():
    hosts = [];ips = [];urls = []
    if len(sys.argv) > 1:
        for i in range(2, len(sys.argv)):
            data,host=check_ip(sys.argv[i])
            master[host]=data
            hosts.append(host)
            ips.append(data['ip'])
            urls.append(data['url'])

    else:
        i = input(style.bold(style.blue("[] Enter Host : ")))
        for i in i.split(' '):
            data, host = check_ip(i)
            master[host]=data
            hosts.append(host)
            ips.append(data['ip'])
            urls.append(data['url'])

def net_input():
    pass


def get_input():
    if len(sys.argv)>1:
        flag=int(sys.argv[1])
        if flag==1:
            hosts_input()
        elif flag==2:
            net_input()
        else:
            pass
    else:
        print("[] 1. Analyze Host/s   []")
        print("[] 2. Analyze Network  []")
        print("[] 0. Exit             []")

        flag=int(input("[] Choice : "))
        if flag==0:
            sys.exit("[]  Thanks For Using  []")
        elif flag==1:
            hosts_input()
        elif flag==2:
            net_input()
        else:
            pass




#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
if 'win' in str(sys.platform).lower():
    python = 'python'
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    if is_admin():
        get_input()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        get_input()
elif 'linux' in str(sys.platform).lower():
    python = 'python3'
    if not os.geteuid() == 0:
        sys.exit('This script must be run as root!')
    else:
        get_input()


print(master)