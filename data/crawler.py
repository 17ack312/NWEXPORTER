import bane
import os
import sys
import tempfile
import shutil
import requests

path = tempfile.gettempdir().replace('\\', '/') + '/newxp/'
#path='E:/UGC/'
python=''

mod = path + 'module/'
out = mod.replace('module', 'out')

if 'win' in str(sys.platform).lower():
    python='py'
elif 'linux' in str(sys.platform).lower():
    python = 'python3'


def _crdir(path):
    try:
        os.mkdir(path)
    except:
        pass

def _rmdir(path):
    if (os.path.exists(path)):
        shutil.rmtree(path)

def _run(comm):
    res=(os.popen(python + ' ' + comm).read())
    return res

def _run_comm(comm):
    res = (os.popen(comm).read())
    return res

def _moddump(f):
    git_url = str('https://raw.githubusercontent.com/17ack312/UGC/main/####').replace('####', f)
    f = open(mod + str(f), 'w', encoding="utf-8")
    f.write(requests.get(git_url,timeout=2).content.decode())
    f.close()


#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

def bane_crawl(link):
    result=[]
    res=bane.crawl(link , timeout=10 )
    for i in list(res.keys()):
        for j in (list(res[i])):
            if 'http' in (j):
                result.append(j)
    res=list(set(result))
    return res


def subdmain(link):
    result=[]
    """
    res=_run(mod+'sublister.py '+link)
    for i in res.split('\n'):
        if '[-]' not in i and len(i)>5:
            result.append(i.split('m',1)[-1].strip().removesuffix('\x1b[0m').strip())
    result=list(set(result))
    """
    res=bane.subdomains_finder(link)

    return res

#print(subdmain(sys.argv[1]))





