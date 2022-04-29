import os, sys, subprocess, ctypes, tempfile, shutil,json,datetime,time,re
import style
import requests, urllib3
import nmap
from json.decoder import JSONDecodeError
from tqdm import *
from rich.progress import track
from data import scanner,vuln
#,crawler


nm = nmap.PortScanner()

master={};hosts=[];ips=[];urls=[]
python=''
path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'
#path='E:/UGC/'
mod = path + 'module/'
out = mod.replace('module', 'out')

def _cls():
	try:
		os.system('clear')
	except:
		os.system('cls')

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
    #for i in res.keys():
    #    res = res[i]
    return res

def get_status(host):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        res = requests.get(host, verify=False,timeout=2).status_code
    except:
        res = 0
    return res

def _run(comm):
    res = (os.popen(python + ' ' + comm).read())
    return res

def _run_comm(comm):
    res = (os.popen(comm).read())
    return res

def _moddump(f):
    git_url = str('https://raw.githubusercontent.com/17ack312/UGC/main/####').replace('####', f)
    f = open(mod + str(f), 'w', encoding="utf-8")
    f.write(requests.get(git_url,timeout=2).content.decode())
    f.close()

_crdir(path)
_crdir(mod)
_crdir(out)

_cls()

def get_url(hnms,ip):
	temp=hnms
	temp.append(ip)
	u=''

	for x in temp:
		url='https://'+str(x)+'/'
		stat=int(get_status(url))
		if stat!=200:
			url=url.replace('https://','http://')
			stat=int(get_status(url))
		if stat==200:
			u=str(url)
			break
	return u
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

def analyze_hosts():
	_cls()
	print(style.bold(style.blue("\n[>] ANALYZING HOST(S) [<]\n")))
	temp=[]

	if (len(sys.argv)) > 2:
		for x in range(2,len(sys.argv)):
			if os.path.exists(sys.argv[x].replace('\\','/')):
				try:
					f=open(sys.argv[x].replace('\\','/'),'r',encoding='utf-8').read()
					for y in f.replace(' ','\n').split('\n'):
						if len(y)>3:
							temp.append(y)
				except:
					pass
			else:
				temp.append(sys.argv[x])
	else:
		temp=input("[>] Enter Host(s) Separated by Space : ").split(' ')
	
	temp=list(set(temp))

	print(style.bold(style.yellow("[>] Preparing For Scanning... ")))

	c=1
	for i in track(temp,description="Getting Host Info... ",total=len(temp)):
		x=str(i).removeprefix('http://').removeprefix('HTTP://').removeprefix('https://').removeprefix('HTTPS://').split('/')[0]
		print(style.green('\n['+str(c)+'] Host :',str(x)))
		hosts.append(x)

		res=_scan(x,'-sn')

		for j in res:
			z={};ip='';mac='';hnms=[]
			try:
				state=str(res[j]['status']['state'])
				if state.lower()=='up':

					try:
						ip=str(res[j]['addresses']['ipv4'])
					except:
						continue
					try:
						mac=str(res[j]['addresses']['mac'])
					except:
						mac=''
					try:
						for y in res[j]['hostnames']:
							hnms.append(y['name'])
					except:
						pass
			except:
				pass

			hnms=list(set(hnms))

			if ip!=None:
					print(style.yellow('\t[✔] IP : ')+str(ip),end="")
					ips.append(ip)
					print(style.yellow('\t[✔] MAC : ')+str(mac),end="")
					print(style.yellow('\t[✔] HOSTNAMES : ')+str(hnms))

					z['ip']=str(ip)
					z['names']=str(hnms)
					z['mac']=str(mac)

					url=get_url(hnms,ip)
					urls.append(url)

					
					z['url']=str(url)

					master[x]=z
		c+=1


def analyze_network():
	_cls()
	print(style.bold(style.blue("\n[>] ANALYZING NETWORK(S) [<]\n")))
	temp=[]

	if (len(sys.argv)) > 2:
		for x in range(2,len(sys.argv)):
			if os.path.exists(sys.argv[x].replace('\\','/')):
				try:
					f=open(sys.argv[x].replace('\\','/'),'r',encoding='utf-8').read()
					for y in f.replace(' ','\n').split('\n'):
						if len(y)>3:
							temp.append(y)
				except:
					pass
			else:
				temp.append(sys.argv[x])
	else:
		temp=input("[>] Enter Network(s) Separated by Space : ").split(' ')

	temp=list(set(temp))
	
	print(style.bold(style.yellow("[>] Preparing For Scanning... \n")))

	c=1
	for i in (temp):
		print(style.green('\n['+str(c)+'] Network :',str(i)))
		res=_scan(i,'-sn')
		
		d=1
		for x in track(res,description='Progress... '):
			z={};ip='';mac='';hnms=[]
			try:
				state=str(res[x]['status']['state'])
				if state.lower()=='up':
					try:
						ip=str(res[x]['addresses']['ipv4'])
					except:
						continue
					try:
						mac=str(res[x]['addresses']['mac'])
					except:
						mac=''
					try:
						for y in res[x]['hostnames']:
							hnms.append(y['name'])
					except:
						pass
			except:
				pass

			hnms=list(set(hnms))

			if ip!=None:
					print(style.yellow('\t['+str(d)+'] IP : ')+str(ip),end="")
					ips.append(ip)
					hosts.append(ip)
					print(style.yellow('\t[✔] MAC : ')+str(mac),end="")
					print(style.yellow('\t[✔] HOSTNAMES : ')+str(hnms),end="\n")

					z['ip']=str(ip)
					z['names']=str(hnms)
					z['mac']=str(mac)

					url=get_url(hnms,ip)
					urls.append(url)

					z['url']=str(url)

					master[ip]=z

					d+=1
		c+=1

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def get_input():
	try:
		flag=int(sys.argv[1])
	except:
		flag=int(banner.menu1())

	if flag==1:
		analyze_hosts()
	if flag==2:
		analyze_network()
	if flag==0:
		sys.exit("Thanks For Using")


#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

if 'win' in str(sys.platform).lower():
    python = 'py'
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
        sys.exit('[] This script must be run as root!')
    else:
        get_input()

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

for m in master.keys():
	ip=str(master[m]['ip'])
	print(vuln.scanner(ip))
	#print(scanner.ext(ip))

