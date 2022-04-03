import os, sys, subprocess, ctypes, tempfile, shutil,json,datetime,time,re
import style
import requests, urllib3
import nmap

from json.decoder import JSONDecodeError
from tqdm import *
from rich.progress import track

nm = nmap.PortScanner()

try:
	os.system('clear')
except:
	os.system('cls')



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


#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
class _banner_():
    def menu1():
        x='''
        [==================================]
        [>>>     CHOOSE  FROM  BELOW    <<<]
        [==================================]
        |>    [1]  ANALYZE  HOST(S)       <|
        |>    [2]  ANALYZE  NETWORK(S)    <|
        |>    [0]  EXIT                   <|
        [==================================]
        '''
        print(style.bold(style.blue(x)))

    def menu2():
        x='''
        [====================================]
        [>>>     CHOOSE   FROM   BELOW    <<<]
        [====================================]
        |>   [1]  VULNERABILITY SCANNING    <|
        |>   [0]  EXIT                      <|
        [====================================]
        '''
        print(style.bold(style.blue(x)))

    def logo():
        print(style.bold(style.yellow("                                  <==>                                          ")))
        print(style.bold(style.yellow("                                   ||                                           ")))
        print(style.bold(style.yellow(" ____   ______  __     ___   _ <========>    ____  ______  _____  _____   _____                                      ")))
        print(style.bold(style.yellow("  | |\  | |  | | |    | \ \ /    ||   |__)) | |  |  | |__)  | |   | |  |  | |__)                                      ")))
        print(style.bold(style.yellow("  | | \ | |=   | | /\ |  \ \     ||   |     | |  |  | |\ \  | |   | |=    | |\ \                                         ")))
        print(style.bold(style.yellow(" _|_|  \|_|___||_|/  \| _/\_\    ||   |     |_|__|  |_| \_| |_|   |_|___| |_| \_|                                             ")))
        print(style.bold(style.yellow("                                 ||   |                                           ")))
        print(style.bold(style.yellow("                                 ||  /                                            ")))
        print(style.bold(style.yellow("                                 || /                                             ")))
        print(style.bold(style.yellow("                                 ||/                                             ")))
        print(style.bold(style.yellow("                                 |/                                             ")))
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def service_info(flag,ip,host):
	#_moddump('_serv.py')

	#for i in track(range(len(ips)),description="Scanning Ports & Services... ",total=len(ips)):		
	if flag==1:
		comm='"'+mod+'_serv.py" 1 '+str(ip)
		res=json.loads(_run(comm).replace("'",'"'))
		master[host]['tcp_serv']=res

	if flag==2:
		comm='"'+mod+'_serv.py" 2 '+str(ip)
		res=json.loads(_run(comm).replace("'",'"'))
		master[host]['udp_serv']=res

	return res

def vuln():
	#_cls()
	print(style.bold(style.yellow('\n[>] Getting Ready For Vulnerability Scanning...')))
	print(style.bold(style.yellow('[>] Total :'+str(len(master)))))

	category=['ssh.py','smtp.py','ssl.py','http.py','rpc.py','ftp.py','dns.py']
	#category=['rpc.py']

	def vuln_scan(file,ip,host):
		try:
			_moddump(file)
			comm=mod+str(file)+' '+str(ip)
			res=json.loads(_run(comm))
			#os.remove(mod+str(file))
			_rmdir(mod+'__pycache__')
		except:
			res={}

		if len(res)==0:
			try:
				_moddump(file)
				comm=mod+str(file)+' '+str(host)
				res=json.loads(_run(comm))
				#os.remove(mod+str(file))			
				_rmdir(mod+'__pycache__')
			except:
				res={}

		return res
		

	count=1
	for i in tqdm(range(len(ips)),desc="Scan in Progress...",total=len(ips)):
		print(style.green('\n['+str(count)+'] Host :',str(hosts[i])),end="")
		print(style.yellow(' => IP :',str(ips[i]),'\n'))

		"""
		print(style.light_yellow('\t[>] Looking For Open Ports...'))
		res=service_info(1,ips[i],hosts[i])
		print(style.on_blue('\t[PORTS]\t\t[SERVICES]\t'))
		if 'port' in res.keys():
			for p in res['port']:
				print(style.cyan('\t[TCP] '+str(p).replace(',','\t',1)))
		res=service_info(2,ips[i],hosts[i])
		if 'port' in res.keys():
			for p in res['port']:
				print(style.cyan('\t[UDP] '+str(p).replace(',','\t',1)))
		"""

		print(style.light_yellow('\n\t[>] Looking For Vulnerabilities'))

		x=[]
		for c in track(category,description="\tStatus"):
			print()
			res=vuln_scan(c,ips[i],hosts[i])

			for r in res:

				if '[INFO]' in r:
					print(style.on_cyan('\t'+str(r)+' \n'))
				if '[LOW]' in r:
					print(style.on_green('\t'+str(r)+' \n'))
				if '[MED]' in r:
					print(style.on_yellow('\t'+str(r)+' \n'))
				if '[HIGH]' in r :
					print(style.on_light_red('\t'+str(r)+' \n'))
				if'[CRIT]' in r:
					print(style.on_red('\t'+str(r)+' \n'))

				x.append(res[r])

				"""	
				if re.search('[INFO]',r):
					print(style.on_cyan(str(r)+' '))

				if re.search('[LOW]',r):
					print(style.on_green(str(r)+' '))				

				if re.search('[MED]',r):
					print(style.on_yellow(str(r)+' '))

				if re.search('[HIGH]',r):
					print(style.on_light_red(str(r)+' '))

				if re.search('[CRIT]',r):
					print(style.on_red(str(r)+' '))
				"""

		master[hosts[i]]['vuln_details']=x


		count+=1




#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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

def lookup():
	print(style.bold(style.yellow('\n[>] Looking Up...')))
	pass

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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
					print(style.yellow('  [✔] IP : ')+str(ip),end="")
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
					print(style.yellow('  ['+str(d)+'] IP : ')+str(ip),end="")
					ips.append(ip)
					hosts.append(ip)
					print(style.yellow('\t[✔] MAC : ')+str(mac),end="")
					print(style.yellow('\t[✔] HOSTNAMES : ')+str(hnms))

					z['ip']=str(ip)
					z['names']=str(hnms)
					z['mac']=str(mac)

					url=get_url(hnms,ip)
					urls.append(url)

					z['url']=str(url)

					master[ip]=z

					d+=1
		c+=1

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def get_input():
	_cls
	_banner_.logo()
	time.sleep(2)

	temp=[]
	try:
		flag=int(sys.argv[1])
	except:
		_banner_.menu1()
		flag=int(input(style.bold(style.blue("[>] Your Choice : "))))

	if flag==1:
		analyze_hosts()
	if flag==2:
		analyze_network()
	if flag==0:
		sys.exit("Thanks For Using")

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::




#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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
_banner_.menu2()
#flag=int(input(style.bold(style.blue("[>] Your Choice : "))))
flag=1

if flag==1:
	vuln()


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
print()
print("==========================================================\n")
#print(ips)
#print(hosts)
#print(urls)
print("\n========================================================\n")
print(master)

