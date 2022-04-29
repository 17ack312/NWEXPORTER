import bane
import os
import sys

domain=IP=link=sys.argv[1]

#res=bane.xss_forms(link , payload="<script>alert(123)</script>" , timeout=15 )
#res=bane.path_traversal_urls(link, timeout=15 )
#res=bane.hsts(link, timeout=15 )
#res=bane.cors_misconfigurations(link, timeout=15 )

#res=bane.http()
#res=bane.forms_parser(link , timeout=10 )
#res=bane.inputs(link , value=True , timeout=10 )
#res=bane.crawl(link , timeout=10 )
#res=bane.subdomains_extract(link , timeout=10 )


#res=bane.get_banner(IP , p='443' , payload=None , timeout=5 )
#res=bane.myip()

#es=bane.norton_rate(link , timeout=15 )
#res=bane.headers( link )
#res=bane.reverse_ip_lookup( IP )
#res=bane.resolve( domain , server="8.8.8.8" )


print(res)