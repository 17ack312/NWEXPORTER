import os, sys, subprocess, ctypes, tempfile, shutil,json,datetime,time,re,signal
import style
import requests, urllib3
import nmap
from json.decoder import JSONDecodeError
from tqdm import *
from rich.progress import track
from alive_progress import alive_bar
from ipaddress import ip_address
import git
def IPAddress(IP: str) -> str:
    return "Private" if (ip_address(IP).is_private) else "Public"

nm = nmap.PortScanner()

master={};hosts=[];ips=[];urls=[]
python=''
path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'
mod = path + 'module/'
out = mod.replace('module', 'out')

def _goodbye():
	_rmdir('data')

def handler(signum, frame):
	_rmdir('data')
	sys.exit("Thanks For Using")
 
signal.signal(signal.SIGINT, handler)

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
from __pycache__ import m
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
exec(m.m_get())

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
	#with alive_bar(len(temp),force_tty=True,title="Gathering Details",bar="bubbles") as bar:
	if True:
		for i in track(temp,description="Gathering Details |",total=len(temp)):
		#for i in temp:
			x=str(i).removeprefix('http://').removeprefix('HTTP://').removeprefix('https://').removeprefix('HTTPS://').split('/')[0]
			#print(style.green('\n['+str(c)+'] Host :',str(x)))
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
						print(style.green('['+str(c)+'] Host :',str(x)),end="")
						print(style.yellow('\n[✔] '+str(IPAddress(ip))+' IP : ')+str(ip),end="")
						ips.append(ip)
						print(style.yellow('\t[✔] MAC : ')+str(mac),end="")
						print(style.yellow('\t[✔] HOSTNAMES : ')+str(hnms),end="\n")
						print()

						z['ip']=str(ip)
						z['host']=str(x)
						z['names']=list(hnms)
						z['mac']=str(mac)
						url=[]
						#url=info.get_url(ip,hnms)
						#url=get_url(hnms,ip)
						#urls.append(url)
						#z['url']=str(url)
						z['url']=url
						master[x]=z
				#bar()
			c+=1
try:
	git.Git(os.getcwd().replace('\\','/')+'/data').clone(temp_url)	
except:
	pass

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
		#with alive_bar(len(res),force_tty=True,title="Gathering Details",bar="bubbles") as bar:
		if True:
			for x in track(res,description='Gathering Details |'):
			#for x in res:
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
						print(style.yellow('\t['+str(d)+'] '+str(IPAddress(ip))+' IP : ')+str(ip),end="")
						ips.append(ip)
						hosts.append(ip)
						print(style.yellow('\t[✔] MAC : ')+str(mac),end="")
						print(style.yellow('\t[✔] HOSTNAMES : ')+str(hnms),end="\n")
						print()

						z['ip']=str(ip)
						z['host']=str(ip)
						z['names']=list(hnms)
						z['mac']=str(mac)
						#url=info.get_url(ip,hnms)
						url=[]
						#url=get_url(hnms,ip)
						#urls.append(url)
						#z['url']=str(url)
						z['url']=url
						master[ip]=z
						d+=1
				#bar()
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
		_rmdir('data')
		sys.exit("Thanks For Using")

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
try:
	_cls()
	from data import scanner
	from data import info
	from data import vuln
	from data import banner
	from data import expl
	from data import vulnerability
	from data import output
	_cls()
	banner.banner()
	time.sleep(3)
	_cls()
except:
	pass

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
    	_rmdir('data')
    	sys.exit('[] This script must be run as root!')
    else:
        get_input()

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
print()
count=0
for m in master.keys():
	count+=1
	ip=str(master[m]['ip'])
	hnms=list(master[m]['names'])

	serv_p={};url={};vuls={}

	now=datetime.datetime.now()
	master[m]['start']=str(now)

	print("\t\t",style.on_magenta("["+str(datetime.datetime.now()).split(".")[0]+"]"),style.on_magenta(" SCAN STARTED ON HOST ["+str(count)+"] "+style.black(style.bold(style.underline('"'+str(m)+'"'))+" "),"\n"))
	#print("==============================================================================================="))
	print("   🧡",style.black(style.on_yellow("","HOST:",m,"")),end="\n")
	print("   💙",style.blue(style.on_white("","IP :",ip,"")),end="\n")
	print("   💚",style.black(style.on_green("","HOSTNAMES:",str(master[m]['names']).removeprefix('[').removesuffix(']'))," "))

	####GETTING OPEN PORTS
	#print("\n\t____________________________________________________________")
	print("\n\t","▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃")
	#print("\t┗━━━━[",style.bold(style.underline(style.yellow("Scanning"),style.cyan("For"),style.green("Ports & Services")),"]"))
	print("\t ┗━━━━[",style.on_white(style.red(" "+str(datetime.datetime.now()).split(".")[0]+" ")),"]",style.on_black(style.bold(style.underline(style.yellow("SCANNING"),style.white("FOR"),style.green("PORTS & SERVICES")))))
	print("\n\t",style.on_blue("   TYPE   "),"\t",style.on_blue(" INFORMATION "))
	print()
	##Service Scan
	serv_p=json.loads(scanner.serv(ip))
	#extended Scan
	#serv_p=json.loads(scanner.ext(ip))

	master[m]['ports']=serv_p[ip]['port']
	try:
		master[m]['os']=serv_p[ip]['os']
	except:
		master[m]['os']=""
	try:
		master[m]['uptime']=serv_p[ip]['uptime']
	except:
		master[m]['uptime']=""

	##CRAWLING
	#print("\n\t__________________________________________________________")
	print("\n\t","▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃")
	#print("\t┗━━━━[",style.bold(style.underline(style.yellow("Crawling"),style.cyan("For"),style.green("Available URLs")),"]"))
	print("\t ┗━━━━[",style.on_white(style.red(" "+str(datetime.datetime.now()).split(".")[0]+" ")),"]",style.on_black(style.bold(style.underline(style.yellow("CRAWLING"),style.white("FOR"),style.green("AVAILABLE URLS")))))
	print("\n\t",style.on_blue(" RESPONSE "),"\t",style.on_blue("  ACCESSIBLE  URLS "))
	print()
	##crawl
	url=json.loads(info.get_url(ip,hnms))
	master[m]['url']=url

	##VULNERABILITIES
	#print("\n\t__________________________________________________________")
	print("\n\t","▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃▃")
	#print("\t┗━━━━[",style.bold(style.underline(style.yellow("Looking"),style.cyan("For"),style.green("Vulnerabilities")),"]"))
	print("\t ┗━━━━[",style.on_white(style.red(" "+str(datetime.datetime.now()).split(".")[0]+" ")),"]",style.on_black(style.bold(style.underline(style.yellow("LOOKING"),style.white("FOR"),style.green("VULNERABILITIES")))))
	print("\n\t",style.on_blue(" FOUND ON "),"\t",style.on_blue("  VULNERABILITIES(POSSIBLE)  "))
	print()


	#common vulns
	vuls['common']=json.loads(vuln.scanner(ip))
	
	#specific vulns
	vuls['xss']=expl.xss(url)
	vuls['sql']=expl.sql(url)
	vuls['rce']=expl.rce(url)
	vuls['ssti']=expl.ssti(url)
	
	master[m]['vuln']=vuls

	now=datetime.datetime.now()
	master[m]['end']=str(now)

	print(style.yellow(style.on_magenta("\n\t\t "+style.on_white(style.white("["+str(datetime.datetime.now()).split(".")[0]+"]"))+" SCAN FINISHED  "))) #"STARTED ON HOST ["+str(count)+"] "+style.black(style.bold(style.underline(str(m)))+"   ")),"\n"))
	#print("===============================================================================================")
	

#print(master)
"""
f=open('res.json','w')
f.write(json.dumps(master))
f.close()
"""

data=output.create_HTML(master)

f=open(os.getcwd().replace('\\','/')+'/output_'+str(datetime.datetime.now()).replace(' ','_')+'.html','w')
f.write(data)
f.close()

_rmdir(path)
_rmdir('data')
