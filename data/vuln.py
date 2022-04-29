import os,sys,nmap
import re ,datetime,json
import style
from alive_progress import alive_bar

nm=nmap.PortScanner()
#python=sys.argv[2]

result={}
ports=[]

def display(r):
    if '[INFO]' in r:
        print(style.on_cyan('\t'+str(r)))
    if '[LOW]' in r:
        print(style.on_green('\t'+str(r)))
    if '[MED]' in r:
        print(style.on_yellow('\t'+str(r)))
    if '[HIGH]' in r :
        print(style.on_light_red('\t'+str(r)))
    if'[CRIT]' in r:
        print(style.on_red('\t'+str(r)))

def _scan(ip, arg):
    res = nm.scan(hosts=ip, arguments=arg)['scan']
    for i in res.keys():
        res = res[i]
    return res

def get_risk(score,flag):
    pass

def output(result):
    res = sorted(result.items(), key = lambda x: x[1]['score'],reverse=True)
    result={}
    for i in res:
        x=i[0]
        y=dict(i[1])
        result[x]=y
    return json.dumps(result)

def filter_data(res):
    if 'tcp' in res.keys():
        data=res['tcp']
        process_data(data)
    if 'udp' in res.keys():
        data=res['udp']
        process_data(data)

    return (output(result))


def set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,serv):
    vuln={}
    vuln['name'] = str(v_name)
    vuln['score'] = float(score)
    vuln['string'] = str(strng)
    vuln['risk'] = str(risk)
    vuln['desc'] = str(desc)
    vuln['imp'] = str(imp)
    vuln['sol'] = str(sol)
    vuln['ref'] = str(ref)
    vuln['link'] = str(link)
    vuln['port']=str(port)
    vuln['service']=str(serv)
    vuln['output']=str(script)
    return vuln

def process_data(data):
    for i in data.keys():
        if 'script' in (data[i].keys()) and str(data[i]['state'])=='open':
            port=str(i)
            ports.append(port)
            name=str(data[i]['name'])
            for j in (data[i]['script'].keys()):
                script=data[i]['script'][j]
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: S S H :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                #1              
                if str(j)=='sshv1':
                    if re.search('Server supports SSHv1',script,re.IGNORECASE):
                        v_name='SSH server supports SSH protocol v1 clients'
                        score=7.5
                        strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
                        risk='High'
                        desc='The SSH server support SSH version 1 clients. Version 1 of the SSH protocol contains fundamental weaknesses which make sessions vulnerable to man-in-the-middle attacks.'
                        imp='The SSH-1 protocol allows remote servers conduct man-in-the-middle attacks and replay a client challenge response to a target server by creating a Session ID that matches the Session ID of the target, but which uses a public key pair that is weaker than the target\'s public key, which allows the attacker to compute the corresponding private key and use the target\'s Session ID with the compromised key pair to masquerade as the target.'
                        sol='ssh-require-protocol-version-2'
                        ref='CVE-2001-1473,CWE:310'
                        link='http://www.kb.cert.org/vuls/id/684820,https://exchange.xforce.ibmcloud.com/vulnerabilities/6603'

                        head='[HIGH] SSH V1 is SUPPORTED'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                
                #2
                if str(j)=='ssh2-enum-algos':
                    for x in (script.replace('\r','').strip().replace('\n','#').replace('kex_algorithms:','\nkex_algorithms:').replace('server_host_key_algorithms:','\nserver_host_key_algorithms:').replace('encryption_algorithms:','\nencryption_algorithms:').replace('mac_algorithms:','\nmac_algorithms:').replace('compression_algorithms:','\ncompression_algorithms:')).split('\n'):
                        if re.search('encryption_algorithms:',x,re.IGNORECASE) and (re.search('arcfour',x,re.IGNORECASE)):
                            v_name='SSH Weak Algorithms Supported'
                            score=4.3
                            strng='CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N'
                            risk='Medium'
                            desc='The remote SSH server is configured to allow weak encryption algorithms or no algorithm at all.'
                            imp='The server supports one or more weak key exchange algorithms. It is highly adviseable to remove weak key exchange algorithm support from SSH configuration files on hosts to prevent them from being used to establish connections.'
                            sol='To disable SSH weak algorithms supported in Linux you need to Disable SSH Server Weak and CBC Mode Ciphers and SSH Weak MAC Algorithms. Follow the articles given below to disable ssh weak algorithms support in a Linux server.\ni) Disable SSH Server Weak and CBC Mode Ciphers in Linux.\nii) Disable SSH Weak MAC Algorithms in Linux'
                            ref=''
                            link='https://tools.ietf.org/html/rfc4253#section-6.3'

                            head=' [MED] SSH WEAK ALGORITHM SUPPORTED'
                            
                            display('[PORT:'+str(port)+']\t'+head)
                            result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                        if re.search('encryption_algorithms:',x,re.IGNORECASE) and (re.search('cbc',x,re.IGNORECASE)):
                            v_name='SSH Server CBC Mode Ciphers Enabled'
                            score=2.6
                            strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                            risk='Low'
                            desc='The SSH server is configured to use Cipher Block Chaining.'
                            imp='The SSH server is configured to support Cipher Block Chaining (CBC) encryption. This may allow an attacker to recover the plaintext message from the ciphertext.'
                            sol='Contact the vendor or consult product documentation to disable CBC mode cipher encryption, and enable CTR or GCM cipher mode encryption.'
                            ref='CVE-2008-5161,CWE:200,CERT:958563'
                            link=''

                            head=' [LOW] SSH CBC MODE CIPHERS ENABLED'
                            
                            display('[PORT:'+str(port)+']\t'+head)
                            result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                        if re.search('mac_algorithms:',x,re.IGNORECASE) and (re.search('hmac',x,re.IGNORECASE)):
                            v_name='SSH Weak MAC Algorithms Enabled'
                            score=2.6
                            strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                            risk='Low'
                            desc='The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.'
                            imp='The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.'
                            sol='Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.'
                            ref='CVE-2008-5161'
                            link='https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/'

                            head=' [LOW] SSH WEAK MAC ALGORITHM DETECTED'
                            
                            display('[PORT:'+str(port)+']\t'+head)
                            result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    

                        if re.search('kex_algorithms:',x,re.IGNORECASE) and (re.search('-sha1',x,re.IGNORECASE) or re.search('non-elliptic-curve',x,re.IGNORECASE) or re.search('rsa1024',x,re.IGNORECASE)):
                            v_name='SSH Weak MAC Algorithms Enabled'
                            score=2.6
                            strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N'
                            risk='Low'
                            desc='The remote SSH server is configured to allow MD5 and 96-bit MAC algorithms.'
                            imp='The remote SSH server is configured to allow either MD5 or 96-bit MAC algorithms, both of which are considered weak.'
                            sol='Contact the vendor or consult product documentation to disable MD5 and 96-bit MAC algorithms.'
                            ref='CVE-2008-5161'
                            link='https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/'

                            head=' [LOW] SSH WEAK MAC ALGORITHM DETECTED'
                            
                            display('[PORT:'+str(port)+']\t'+head)
                            result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                #3
                if str(j)=='ssh-hostkey':
                    #print(script)
                    pass

                #4
                if str(j)=='ssh-publickey-acceptance':
                    #print(script)
                    pass

                #5
                if str(j)=='ssh-auth-methods':
                    #print(script)
                    pass

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: S S L ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                #1
                if str(j)=='ssl-cert':
                    for x in (script).split('\n'):
                        if re.search('Not valid after',x,re.IGNORECASE):
                            s_date=(x.split(':',1)[1].split('T')[0].strip())
                            s_date=(datetime.datetime(int(s_date.split('-')[0]),int(s_date.split('-')[1]),int(s_date.split('-')[2])))
                            if s_date<datetime.datetime.now():
                                v_name='SSL Certificate Expiry'
                                score=5.3
                                strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                                risk='Medium'
                                desc="The SSL certificate has already expired."
                                imp="When you have an SSL certificate properly installed, your server will engage in something called the SSL handshake anytime a visitor wants to make a connection. During this handshake, the user’s browser will be presented with the site’s SSL certificate. It needs to authenticate the certificate in order to complete the handshake.The authentication process requires the certificate to be within its validity dates. Every certificate has an issued and expired data coded into it. This allows the browser to determine whether it’s still valid or has expired. If the certificate is expired, the user’s browser has no way to validate the server. That means it can’t definitively tell you if the website presenting this certificate is its rightful owner.That’s going to cause a browser error that says your connection is not secure. The error is big; it blocks people from getting to your website – effectively breaking the site.Now, depending on how you’ve configured your server — all hope may not be lost. But you’d have to advise your customers to click through a browser warning, which most people aren’t going to do.However, if you’ve set up your website to use HTTP Strict Transport Security (HSTS), clicking through the warning won’t even be an option. HSTS forces secure connections, and if the certificate isn’t valid, the browser won’t be able to make one. In that case, your website is completely broken."
                                sol='Purchase or generate a new SSL certificate to replace the existing one.'
                                ref=''
                                link=''
                                head=' [MED] SSL CERTIFICATE EXPIRED'
                                
                                display('[PORT:'+str(port)+']\t'+head)
                                result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                            
                #2
                if str(j)=='ssl-date':
                    ##DUE
                    pass
                #3
                if str(j)=='ssl-enum-ciphers':
                    if re.search('Weak certificate signature',script,re.IGNORECASE) or re.search('Insecure certificate signature',script,re.IGNORECASE):
                        v_name='SSL Certificate Signed Using Weak Hashing Algorithm'
                        score=7.5
                        strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'
                        risk='High'
                        desc='The remote service uses an  SSL certificate that has been signed using a cryptographically weak hashing  algorithm - MD2, MD4, or MD5. These signature algorithms are known to be  vulnerable to collision attacks.'
                        imp='In theory, a determined attacker may be  able to leverage this weakness to generate another certificate with the same  digital signature, which could allow him to masquerade as the affected  service.'
                        sol='Contact the Certificate Authority to have the SSL certificate reissued.'
                        ref='CVE-2004-2761,CERT:836068,CWE:310'
                        link='https://tools.ietf.org/html/rfc3279,http://www.nessus.org/u?9bb87bf2,http://www.nessus.org/u?e120eea1,http://www.nessus.org/u?5d894816,http://www.nessus.org/u?51db68aa,http://www.nessus.org/u?9dc7bfba'

                        head='[HIGH] SSL CERTIFICATE SIGNED WITH WEAK HASHING ALGORITHMS'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                    

                    if re.search('vulnerable to SWEET32 attack',script,re.IGNORECASE):
                        v_name='SSL Medium Strength Cipher Suites Supported (SWEET32)'
                        score=7.5
                        strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                        risk='High'
                        desc='The remote service supports the use of medium strength SSL ciphers.'
                        imp='The remote host supports the use of SSL ciphers that offer medium strength encryption.Any encryption that uses key lengths at least 64 bits and less than 112 bits, or else that uses the 3DES encryption suite.'
                        sol = 'Reconfigure the affected application if possible to avoid use of medium strength ciphers.'
                        ref = 'CVE-2016-2183'
                        link = 'https://www.openssl.org/blog/blog/2016/08/24/sweet32/,https://sweet32.info'

                        head='[HIGH] SSL CIPHERS VULNERABLE TO SWEET32 ATTACK'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    """
                    if re.search('Key exchange') and re.search('of lower strength than certificate key',script,re.IGNORECASE):
                        v_name='SSL/TLS Diffie-Hellman Modulus'
                        score=3.7
                        strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'
                        risk='Low'
                        desc='The remote host allows SSL/TLS connections with one or more Diffie-Hellman moduli less than or equal to 1024 bits.'
                        imp='The remote host allows SSL/TLS connections with one or more Diffie-Hellman moduli less than or equal to 1024 bits. Through cryptanalysis, a third party may be able to find the shared secret in a short amount of time (depending on modulus size and attacker resources). This may allow an attacker to recover the plaintext or potentially violate the integrity of connections.'
                        sol='Reconfigure the service to use a unique Diffie-Hellman moduli of 2048 bits or greater.'
                        ref='CVE-2015-4000'
                        link='https://weakdh.org/'

                        head=' [LOW] SSL/TLS DIFFIE-HELLMAN MODULUS'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)      
                    """

                    if re.search('Broken cipher RC4',script,re.IGNORECASE):
                        v_name='SSL RC4 Cipher Suites Supported'
                        score=5.9
                        strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                        risk='Medium'
                        desc='The remote service supports the use of the RC4 cipher.'
                        imp='The RC4 cipher is flawed in its generation of a pseudo-random stream of bytes so that a wide variety of small biases are introduced into the stream, decreasing its randomness.If plaintext is repeatedly encrypted (e.g., HTTP cookies), and an attacker is able to obtain many (i.e., tens of millions) ciphertexts, the attacker may be able to derive the plaintext.'
                        sol='Reconfigure the affected application, if possible, to avoid use of RC4 ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support.'
                        ref='CVE-2013-2566,CVE-2015-2808'
                        link='https://www.rc4nomore.com/,http://www.nessus.org/u?ac7327a0,http://cr.yp.to/talks/2013.03.12/slides.pdf,http://www.isg.rhul.ac.uk/tls/,https://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf'

                        head=' [MED] SSL CIPHER CHAIN SUPPORTS RC4 CIPHERS WHICH IS DEPRECATED BY RFC 7465'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                    
                #4
                if str(j)=='sslv2-drown':
                    #if re.search('title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)',script) and \
                    if re.search('state: VULNERABLE',script,re.IGNORECASE):
                        v_name='SSL DROWN Attack Vulnerability'
                        score=5.9
                        strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                        risk='Medium'
                        desc='The remote host supports SSLv2 and therefore may be affected by a vulnerability that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption).'
                        imp="This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilizing previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key.The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka a DROWN attack."
                        sol='Disable SSLv2 and export grade cryptography cipher suites. Ensure that private keys are not used anywhere with server software that supports SSLv2 connections.'
                        ref='CVE-2016-0800,CERT:583776'
                        link='https://drownattack.com/,https://drownattack.com/drown-attack-paper.pdf'

                        head=' [MED] SSL CIPHERS VULNERABLE TO DROWN ATTACK'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                    
                #5
                if str(j)=='ssl-ccs-injection':
                    if re.search('State: VULNERABLE',script,re.IGNORECASE):
                        v_name='SSL/TLS MITM vulnerability (CCS Injection)'
                        score=7.4
                        strng='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'
                        risk='High'
                        desc='The remote machine is affected by SSL CSS Injection vulnerability'
                        imp='OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the “CCS Injection” vulnerability.'
                        sol='http-openssl-0_9_8-upgrade-0_9_8_z_a\nhttp-openssl-1_0_0-upgrade-1_0_0_m\nhttp-openssl-1_0_1-upgrade-1_0_1_h'
                        ref='CVE-2014-0224'
                        link='https://attackerkb.com/topics/cve-2014-0224'

                        head='[HIGH] SSL/TLS MITM CSS INJECTION'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #6
                if str(j)=='ssl-dh-params':
                    if re.search('State: VULNERABLE',script,re.IGNORECASE) and re.search('Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)',script,re.IGNORECASE):
                        v_name='Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)'
                        score=5.9
                        strng='CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
                        risk='Medium'
                        desc='The remote service is vulnerable to DHE_EXPORT Ciphers Downgrade MitM attack.'
                        imp='The Transport Layer Security (TLS) protocol contains a flaw that is triggered when handling DiffieHellman key exchanges defined with the DHE_EXPORT cipher. A man-in-the middle attacker may be able to downgrade the session to use EXPORT_DHE cipher suites. Thus, it is recommended to remove support for weak cipher suites.'
                        sol='Upgrade TLS certificate to fixed version'
                        ref='CVE-2015-4000'
                        link='https://www.securityfocus.com/bid/74733,https://weakdh.org'

                        head=' [MED] TLS DHE_EXPORT Ciphers Downgrade MitM (Logjam)'.upper()
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('State: VULNERABLE', script,re.IGNORECASE) and re.search('Diffie-Hellman Key Exchange Insufficient Diffie-Hellman Group Strength',script,re.IGNORECASE):
                        v_name='Diffie-Hellman Key Exchange Insufficient Diffie-Hellman Group Strength'
                        score=4.0
                        strng='CVSS:3.0/AV:N/AC:H/Au:N/C:P/I:P/A:N'
                        risk='Medium'
                        desc='The SSL/TLS service uses Diffie-Hellman groups with insufficient strength (key size < 2048).'
                        imp='The Diffie-Hellman group are some big numbers that are used as base for the DH computations. They can be, and often are, fixed. The security of the final secret depends on the size of these parameters. It was found that 512 and 768 bits to be weak, 1024 bits to be breakable by really powerful attackers like governments.An attacker might be able to decrypt the SSL/TLS communication offline.'
                        sol='Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use a 2048-bit or stronger Diffie-Hellman group (see the references). For Apache Web Servers: Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.'
                        ref=''
                        link='https://weakdh.org'

                        head=' [MED] SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability'.upper()
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    

                    if re.search('State: VULNERABLE', script,re.IGNORECASE) and re.search('Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters',script,re.IGNORECASE):
                        ##DUE
                        v_name='Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters'
                        score=0
                        strng=''
                        risk='None'
                        desc=''
                        imp=''
                        sol=''
                    ref=''
                    link='https://weakdh.org'

                    head='[NONE] Diffie-Hellman Key Exchange Potentially Unsafe Group Parameters'.upper()
                    
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #7
                if str(j)=='ssl-heartbleed':
                    if re.search('State: VULNERABLE', script,re.IGNORECASE):
                        v_name="OpenSSL 'Heartbleed' vulnerability"
                        score=7.5
                        strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                        risk='High'
                        desc='A vulnerability in OpenSSL could allow a remote attacker to expose sensitive data, possibly including user authentication credentials and secret keys, through incorrect memory handling in the TLS heartbeat extension.OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time. Note that an attacker can repeatedly leverage the vulnerability to retrieve as many 64k chunks of memory as are necessary to retrieve the intended secrets. The sensitive information that may be retrieved using this vulnerability include:\ni) Primary key material (secret keys)\nii)Secondary key material (user names and passwords used by vulnerable services)\niii)Protected content (sensitive data used by vulnerable services)\niv)Collateral (memory addresses and content that can be leveraged to bypass exploit mitigations)'
                        imp='This flaw allows a remote attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of 64k at a time.'
                        sol='OpenSSL 1.0.1g has been released to address this vulnerability.  Any keys generated with a vulnerable version of OpenSSL should be considered compromised and regenerated and deployed after the patch has been applied.'
                        ref='CVE-2014-0160'
                        link='https://www.kb.cert.org/vuls/id/720951,https://tools.ietf.org/html/rfc2409#section-8,https://heartbleed.com/'

                        head='[HIGH] VULNERABLE TO OPENSSL HEARTBLEED'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script,name)

                #8
                if str(j)=='ssl-poodle':
                    if re.search('State: VULNERABLE',script,re.IGNORECASE):
                        v_name='SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)'
                        score=6.8
                        strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N'
                        risk='Medium'
                        desc='It is possible to obtain sensitive information from the remote host with SSL/TLS-enabled services.'
                        imp='The remote host is affected by a man-in-the-middle (MitM) information disclosure vulnerability known as POODLE. The vulnerability is due to the way SSL 3.0 handles padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode.MitM attackers can decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.As long as a client and service both support SSLv3, a connection can be rolled back to SSLv3, even if TLSv1 or newer is supported by the client and service.The TLS Fallback SCSV mechanism prevents version rollback attacks without impacting legacy clients; however, it can only protect connections when the client and service support the mechanism. Sites that cannot disable SSLv3 immediately should enable this mechanism.This is a vulnerability in the SSLv3 specification, not in any particular SSL implementation. Disabling SSLv3 is the only way to completely mitigate the vulnerability.'
                        sol='Disable SSLv3.Services that must support SSLv3 should enable the TLS Fallback SCSV mechanism until SSLv3 can be disabled.'
                        ref='CVE-2014-3566,CERT:577193'
                        link='https://www.imperialviolet.org/2014/10/14/poodle.html,https://www.openssl.org/~bodo/ssl-poodle.pdf.https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00'

                        head=' [MED] VULNERABLE TO SSL POODLE'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script,name)
                    
                #9
                if str(j)=='tls-ticketbleed' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='TLS TicketBleed'
                    score=7.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                    risk='High'
                    desc='Ticketbleed is a serious issue in products manufactured by F5, a popular vendor of TLS load-balancers. The issue allows for stealing information from the load balancer'
                    imp='Ticketbleed is vulnerability in the implementation of the TLS SessionTicket extension found in some F5 products. It allows the leakage (\'bleeding\') of up to 31 bytes of data from uninitialized memory. This is caused by the TLS stack padding a Session ID, passed from the client, with data to make it 32-bits long.'
                    sol=''
                    ref='CVE-2016-9244,CWE:200'
                    link='https://www.exploit-db.com/exploits/41298/'

                    head='[HIGH] TLS TICKETBLEED FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head] = set_data(v_name, score, strng, risk, desc, imp, sol, ref, link, port, script,name)
                
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: S M T P :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                #1
                if str(j)=='smtp-commands' and re.search('Commands supported',script,re.IGNORECASE):
                    if re.search('STARTTLS',script,re.IGNORECASE):
                        v_name='SMTP Service Supports STARTTLS Command'
                        score=0.0
                        strng=''
                        risk='Informational'
                        desc='The remote SMTP service supports the use of the \'STARTTLS\' command to switch from a cleartext to an encrypted communications channel.'
                        imp='N/A'
                        sol='N/A'
                        ref=''
                        link='https://en.wikipedia.org/wiki/STARTTLS,https://tools.ietf.org/html/rfc2487'

                        head='[INFO] SMTP SERVICE SUPPORT STARTTLS COMMAND'
                        
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #2
                if str(j)=='smtp-open-relay' and re.search('Server is an open relay',script,re.IGNORECASE):
                    v_name='MTA Open Mail Relaying Allowed'
                    score=7.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
                    risk='High'
                    desc='An open SMTP relay is running on the remote host.'
                    imp='This issue allows any spammer to use your mail server to send their mail to the world, thus flooding your network bandwidth and possibly getting your mail server blacklisted.'
                    sol='Reconfigure your SMTP server so that it cannot be used as an indiscriminate SMTP relay. Make sure that the server uses appropriate access controls to limit the extent to which relaying is possible.'
                    ref='CVE-1999-0512'
                    link='https://en.wikipedia.org/wiki/Email_spam'

                    head='[HIGH] MTA OPEN RELAYING ENABLED'
                    
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #3
                if str(j)=='smtp-strangeport' and re.search('Mail server on unusual port',script,re.IGNORECASE):
                    pass
                    ##DUE
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: H T T P :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                #1
                if str(j)=='http-apache-negotiation' and re.search('mod_negotiation enabled',script,re.IGNORECASE):
                    v_name='Apache mod_negotiation Multiple Vulnerabilities'
                    score=5.3
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='mod_negotiation is an Apache module responsible for selecting the document that best matches the clients capabilities, from one of several available documents. If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error containing a pseudo directory listing. This behaviour can help an attacker to learn more about his target, for example, generate a list of base names, generate a list of interesting extensions, look for backup files and so on.'
                    imp='Multiple vulnerabilities have been found in Apache mod_negotiation: * Cross-site scripting (XSS) vulnerability in the mod_negotiation module in the Apache HTTP Server 2.2.6 and earlier in the 2.2.x series, 2.0.61 and earlier in the 2.0.x series, and 1.3.39 and earlier in the 1.3.x series allows remote authenticated users to inject arbitrary web script or HTML by uploading a file with a name containing XSS sequences and a file extension, which leads to injection within a \'406 Not Acceptable\' or \'300 Multiple Choices\' HTTP response when the extension is omitted in a request for the file.\n i) ap_get_basic_auth_pw() Authentication Bypass :\n\tUse of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed. Third-party module writers SHOULD use ap_get_basic_auth_components(), available in 2.2.34 and 2.4.26, instead of ap_get_basic_auth_pw(). Modules which call the legacy ap_get_basic_auth_pw() during the authentication phase MUST either immediately authenticate the user after the call, or else stop the request immediately with an error response, to avoid incorrectly authenticating the current request.\n ii) mod_ssl Null Pointer Dereference :\n\tmod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port.\n iii) ap_find_token() Buffer Overread :\n\tThe HTTP strict parsing changes added in 2.2.32 and 2.4.24 introduced a bug in token list parsing, which allows ap_find_token() to search past the end of its input string. By maliciously crafting a sequence of request headers, an attacker may be able to cause a segmentation fault, or to force ap_find_token() to return an incorrect value.\n iv) mod_mime Buffer Overread :\n\tmod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.\n v) Uninitialized memory reflection in mod_auth_digest :\n\tThe value placeholder in [Proxy-]Authorization headers of type \'Digest\' was not initialized or reset before or between successive key=value assignments. by mod_auth_digest. Providing an initial key with no \'=\' assignment could reflect the stale value of uninitialized pool memory used by the prior request, leading to leakage of potentially confidential information, and a segfault.\n vi) mod_userdir CRLF injection :\n\tPossible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value.\n vii) mod_status buffer overflow :\n\tA race condition was found in mod_status. An attacker able to access a public server status page on a server using a threaded MPM could send a carefully crafted request which could lead to a heap buffer overflow. Note that it is not a default or recommended configuration to have a public accessible server status page.\n vii) mod_cgid denial of service :\n\tA flaw was found in mod_cgid. If a server using mod_cgid hosted CGI scripts which did not consume standard input, a remote attacker could cause child processes to hang indefinitely, leading to denial of service.\n '
                    sol='Upgrade to Apache version 2.3.2 or newer.'
                    ref='CVE-2008-0455,CVE-2008-0456,CVE-2017-9798,CVE-2017-3167,CVE-2017-3169,CVE-2017-7668,CVE-2017-7679,CVE-2017-9788,CWE:538'
                    link='https://httpd.apache.org/security/vulnerabilities_22.html,https://beyondsecurity.com/scan-pentest-network-vulnerabilities-apache-mod-negotiation-multi-line-filename-upload-vulnerabilities.html#:~:text=Vulnerabilities%20in%20Apache%20mod_negotiation%20Multi-Line%20Filename%20Upload%20is,to%20resolve%20or%20prone%20to%20being%20overlooked%20entirely,https://bz.apache.org/bugzilla/show_bug.cgi?id=46837'

                    head=' [MED] APACHE MOD_NEGOTIATION IS ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #2
                if str(j)=='http-aspnet-debug' and re.search('DEBUG is enabled',script,re.IGNORECASE):
                    v_name='ASP.NET Debugging Enabled'
                    score=5.3
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='The ASP.NET application is running in debug mode which allows a remote user to glean information about an application by using the DEBUG verb in an HTTP request. This can leak information including source code, hidden filenames, and detailed error messages.'
                    imp='ASP.NET debugging is enabled on this application. It is recommended to disable debug mode before deploying a production application. By default, debugging is disabled, and although debugging is frequently enabled to troubleshoot a problem, it is also frequently not disabled again after the problem is resolved. An attacker might use this to alter the runtime of the remote scripts.'
                    sol='Make sure that DEBUG statements are disabled or only usable by authenticated users.'
                    ref='CWE:11'
                    link='https://support.microsoft.com/en-us,https://capec.mitre.org/data/definitions/37.html,https://www.tenable.com/plugins/nessus/33270,https://docs.microsoft.com/en-US/troubleshoot/developer/webapps/aspnet/development/disable-debugging-application'

                    head=' [MED] ASP.NET DEBUGGING ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #3
                if str(j)=='http-avaya-ipoffice-users':# and re.search(,re.IGNORECASE):
                    pass
                    ##DUE

                #4
                if str(j)=='http-awstatstotals-exec.' and re.search('Output for',script,re.IGNORECASE):
                    pass
                    ##DUE

                #5
                if str(j)=='http-comments-displayer':
                    pass
                    ##DUE

                #6
                if str(j)=='http-config-backup':
                    pass
                    ##DUE

                #7
                if str(j)=='http-cookie-flags':
                    if re.search('secure flag not set',script,re.IGNORECASE):
                        v_name='Cookie Not Marked As Secure'
                        score=4.3
                        strng='CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N'
                        risk='Medium'
                        desc='The remote web application uses cookies to track authenticated users. However, there are instances where the application is running over unencrypted HTTP or the cookie(s) are not marked \'secure\', meaning the browser could send them back over an unencrypted link under certain circumstances.'
                        imp='This cookie will be transmitted over a HTTP connection, therefore an attacker might intercept it and hijack a victim\'s session. If the attacker can carry out a man-in-the-middle attack, he/she can force the victim to make an HTTP request to your website in order to steal the cookie.'
                        sol='Host the web application on a server that only provides SSL (HTTPS).Mark all cookies as \'secure\'.'
                        ref='CWE:522,CWE:718,CWE:724,CWE:928,CWE:930'
                        link='http://www.nessus.org/u?1c015bda,https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/session-cookie-not-marked-as-secure/'

                        head=' [MED] COOKIE NOT SECURE'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('httponly flag not set',script,re.IGNORECASE):
                        v_name='Cookie Without HttpOnly Flag Set'
                        score=0.0
                        strng=''
                        risk='Informational'
                        desc='One or more cookies don\'t have the HttpOnly flag set. When a cookie is set with the HttpOnly flag, it instructs the browser that the cookie can only be accessed by the server and not by client-side scripts. This is an important security protection for session cookies.'
                        imp='If the HttpOnly attribute is set on a cookie, then the cookie\'s value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie\'s value via an injected script.'
                        sol='There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie\'s value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing.'
                        ref='CWE:16,CWE:1004'
                        link=''

                        head=' [MED] COOKIE WITHOUT HTTP-ONLY'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #8
                if str(j)=='http-cors':
                    pass
                    ##DUE

                #9
                if str(j)=='http-cross-domain-policy' and re.search('State: VULNERABLE',script,re.IGNORECASE):
                    v_name='Cross-domain Policy File'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The remote web server contains a cross-domain policy file. This is a simple XML file used by Adobe’s Flash Player to allow access to data that resides outside the exact web domain from which a Flash movie file originated.'
                    imp='This is a simple XML file used by Adobe’s Flash Player to allow access to data that resides outside the exact web domain from which a Flash movie file originated.'
                    sol='Review the contents of the policy file carefully. Improper policies, especially an unrestricted one with just ‘*’, could allow for cross-site request forgery and cross-site scripting attacks against the web server.'
                    ref='CVE-2015-7369'
                    link='http://blog.jeremiahgrossman.com/2008/05/crossdomainxml-invites-cross-site.html,http://blogs.adobe.com/stateofsecurity/2007/07/crossdomain_policy_files_1.html'

                    head='[INFO] CROSS DOMAIN POLICY FILE FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #10
                if str(j)=='http-csrf' and re.search('vulnerabilities:',script,re.IGNORECASE):
                    v_name='Possible CSRF (Cross-site request forgery)'
                    score=4.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'
                    risk='Medium'
                    desc='This alert requires manual confirmation.Cross-Site Request Forgery (CSRF, or XSRF) is a vulnerability wherein an attacker tricks a victim into making a request the victim did not intend to make. Therefore, with CSRF, an attacker abuses the trust a web application has with a victim\'s browser.'
                    imp='CSRF will possibly work assuming the potential victim is authenticated. A CSRF attacker can bypass the authentication process to enter a web application when a victim with extra privileges performs activities that are not available to everybody, which is when CSRF attacks are used. Like web-based financial situations.There are two principal parts to executing a Cross-Site Request Forgery (CSRF) attack.\ni) The first part is to fool the victim into clicking a link or loading up a page. This is normally done through social engineering. An attacker will lure the client into tapping the link by utilizing social engineering strategies.\nii) Another part is to send a “forged” or made up request to the client’s browser. This connection will send an authentic-looking request to web application. The request will be sent with values that the attacker needs. Aside from them, this request will include any client’s cookies related to that site. As cookies are sent, the web application realizes that this client can play out specific activities on the web-site based upon the authorization level of the victim. The web applications will think about these requests as unique. However, the victim would send the request at the attacker’s command. A CSRF attack essentially exploits how the browser sends the cookies to the web application consequently with every single request.'
                    sol='Verify if this form requires anti-CSRF protection and implement CSRF countermeasures if necessary.The recommended and the most widely used technique for preventing CSRF attacks is know as an anti-CSRF token, also sometimes referred to as a synchronizer token. The characteristics of a well designed anti-CSRF system involve the following attributes.\ni) The anti-CSRF token should be unique for each user session.\nii) The session should automatically expire after a suitable amount of time.\niii) The anti-CSRF token should be a cryptographically random value of significant length.\niv) The anti-CSRF token should be cryptographically secure, that is, generated by a strong Pseudo-Random Number Generator (PRNG) algorithm.\nv) The anti-CSRF token is added as a hidden field for forms, or within URLs (only necessary if GET requests cause state changes, that is, GET requests are not idempotent).\nvi) The server should reject the requested action if the anti-CSRF token fails validation.\nWhen a user submits a form or makes some other authenticated request that requires a Cookie, the anti-CSRF token should be included in the request. Then, the web application will then verify the existence and correctness of this token before processing the request. If the token is missing or incorrect, the request can be rejected.'
                    ref='CWE:352,CVE-2006-5476'
                    link='https://www.acunetix.com/websitesecurity/csrf-attacks/,https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html,https://www.cgisecurity.com/csrf-faq.html'

                    head=' [MED] POSSIBLE CSRF INJECTION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #11
                if str(j)=='http-default-accounts' and re.search('at /',script,re.IGNORECASE):
                    pass
                    ##DUE

                #12
                if str(j)=='http-dlink-backdoor' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='D-Link Router Authentication Bypass Backdoor Vulnerability'
                    score=0.0
                    strng=''
                    risk='High'
                    desc='A vulnerability was reported in D-Link Routers. A remote user can gain administrative access on the target device.'
                    imp='A remote user can send a specially crafted HTTP request with the HTTP User-Agent set to \'xmlset_roodkcableoj28840ybtide\' to bypass authentication and gain administrative access on the target device.The vulnerability is due to a non-secure backdoor(Elevation of Privilege).'
                    sol='Before installation of the software, please visit the software manufacturer web-site for more details.Update avaliable at http://www.dlink.com/uk/en/support/security (update on 3 Dec 2013)'
                    ref=''
                    link='http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/,http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/,http://securitytracker.com/id/1029174'

                    head='[HIGH] D_LINK BACKDOOR FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #13
                if str(j)=='http-dombased-xss' and re.search('Found the following',script,re.IGNORECASE):
                    v_name='DOM Based Cross-Site scripting'
                    score=6.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
                    risk='Medium'
                    desc='Client-side scripts are used extensively by modern web applications. They perform from simple functions (such as the formatting of text) up to full manipulation of client-side data and Operating System interaction.'
                    imp='Unlike traditional Cross-Site Scripting (XSS), where the client is able to inject scripts into a request and have the server return the script to the client, DOM XSS does not require that a request be sent to the server and may be abused entirely within the loaded page.his occurs when elements of the DOM (known as the sources) are able to be manipulated to contain untrusted data, which the client-side scripts (known as the sinks) use or execute an unsafe way.'
                    sol='Client-side document rewriting, redirection, or other sensitive action, using untrusted data, should be avoided wherever possible, as these may not be inspected by server side filtering.To remedy DOM XSS vulnerabilities where these sensitive document actions must be used, it is essential to:\ni) Ensure any untrusted data is treated as text, as opposed to being interpreted as code or mark-up within the page.\nii) Escape untrusted data prior to being used within the page. Escaping methods will vary depending on where the untrusted data is being used. (See references for details.)\niii) Use `document.createElement`, `element.setAttribute`, `element.appendChild`, etc. to build dynamic interfaces as opposed to HTML rendering methods such as `document.write`, `document.writeIn`, `element.innerHTML`, or `element.outerHTML `etc.'
                    ref='CWE:79'
                    link='http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting,https://www.owasp.org/index.php/DOM_Based_XSS,https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet'

                    head=' [MED] DOM BASED XSS'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #14
                if str(j)=='http-fileupload-exploiter' and re.search('Successfully uploaded',script,re.IGNORECASE):
                    v_name='Unrestricted File Upload Vulnerability'
                    score=9.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
                    risk='Critical'
                    desc='File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.'
                    imp='The impact of file upload vulnerabilities generally depends on two key factors:\n i) Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.\n ii) What restrictions are imposed on the file once it has been successfully uploaded.\nIn the worst case scenario, the file\'s type isn\'t validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.\nIf the filename isn\'t validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations.\nFailing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.'
                    sol='Restrict file types accepted for upload: check the file extension and only allow certain files to be uploaded. Use a whitelist approach instead of a blacklist. Check for double extensions such as .php.png. Check for files without a filename like .htaccess (on ASP.NET, check for configuration files like web.config). Change the permissions on the upload folder so the files within it are not executable. If possible, rename the files that are uploaded.'
                    ref='CWE:434,CVE-2018-15961,CWE:200'
                    link='https://www.owasp.org/index.php/Unrestricted_File_Upload,https://www.acunetix.com/websitesecurity/upload-forms-threat/'

                    head='[CRIT] FILE UPLOAD VULNERABILTY'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #15
                if str(j)=='http-frontpage-login' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    pass
                    ##DUE

                #16
                if str(j)=='http-git' and re.search('Git repository found!',script,re.IGNORECASE):
                    v_name='Git Repository Found'
                    score=5.8
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N'
                    risk='Medium'
                    desc='Git metadata directory (.git) was found in this folder.'
                    imp='An attacker can extract sensitive information by requesting the hidden metadata directory that version control tool Git creates. The metadata directories are used for development purposes to keep track of development changes to a set of source code before it is committed back to a central repository (and vice-versa). When code is rolled to a live server from a repository, it is supposed to be done as an export rather than as a local working copy, and hence this problem.'
                    sol='Remove these files from production systems or restrict access to the .git directory. To deny access to all the .git folders you need to add the following lines in the appropriate context (either global config, or vhost/directory, or from .htaccess)'
                    ref='CWE:527'
                    link='http://www.ducea.com/2006/08/11/apache-tips-tricks-deny-access-to-some-folders/'

                    head=' [MED] GIT REPO FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #17
                if str(j)=='http-gitweb-projects-enum' and re.search('Projects from',script,re.IGNORECASE):
                    pass
                    ##DUE

                #18
                if str(j)=='http-google-malware':# and re.search():
                    pass
                    ##DUE

                #19
                if str(j)=='http-huawei-hg5xx-vuln' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='Remote Credential And Information Disclosure In Modems Huawei HG5XX'
                    score=0.0
                    strng=''
                    risk='Unknown'
                    desc='Modems Huawei 530x, 520x and possibly others are vulnerable to remote credential and information disclosure.'
                    imp='Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to extract sensitive information including PPPoE credentials, firmware version, model, gateway, dns servers and active connections among other values.'
                    sol=''
                    ref=''
                    link='http://routerpwn.com/#huawei,http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure'

                    head=' [???] HUAWEI INFORMATION DISCLOSURE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #20
                if str(j)=='http-iis-short-name-brute' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='Microsoft IIS Tilde Character "~" Short Name Disclosure'
                    score=6.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L'
                    risk='Medium'
                    desc='Microsoft IIS Tilde Character Short File/Folder Name Disclosure'
                    imp='Microsoft Internet Information Server (IIS) suffers from a vulnerability which allows the detection of short names of files and directories which have en equivalent in the 8.3 version of the file naming scheme. By crafting specific requests containing the tilde \'~\' character, an attacker could leverage this vulnerability to find files or directories that are normally not visible and gain access to sensitive information. Given the underlying filesystem calls generated by the remote server, the attacker could also attempt a denial of service on the target application.'
                    sol='As a workaround, disable the 8.3 file and directories name creation, manually remove names already present in the fileystem and ensure that URL requests containing the tilde character (and its unicode equivalences) are discarded before reaching the IIS server.If possible, upgrade to the latest version of the .NET framework and IIS server.'
                    ref='CWE:20'
                    link='https://soroush.secproject.com/blog/2012/06/microsoft-iis-tilde-character-vulnerabilityfeature-short-filefolder-name-disclosure/,https://soroush.secproject.com/blog/2014/08/iis-short-file-name-disclosure-is-back-is-your-server-vulnerable/,https://github.com/irsdl/IIS-ShortName-Scanner,https://support.microsoft.com/en-gb/help/121007/how-to-disable-8-3-file-name-creation-on-ntfs-partitions'

                    head=' [MED] MS IIS SHORTNAME DISCLOSURE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #21
                if str(j)=='http-iis-webdav-vuln' and re.search('is ENABLED',script,re.IGNORECASE):
                    v_name='WebDAV Extension Is Enabled'
                    score=3.9
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N'
                    risk='Low'
                    desc='WebDAV is an extension to the HTTP protocol. It allows authorized users to remotely add and change content on your web server.'
                    imp='If WebDAV is not configured properly it may allow remote users to modify the content of the website.'
                    sol='If you are not using this extension, it\'s recommended to be disabled.'
                    ref='CWE:16'
                    link='http://www.securiteam.com/windowsntfocus/5FP0B2K9FY.html'

                    head=' [LOW] WEBDAV ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #22
                if str(j)=='http-internal-ip-disclosure' and re.search('Leaked',script,re.IGNORECASE):
                    v_name='Internal IP Disclosure'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='One or more strings matching an internal IPv4 address were found. These IPv4 addresses may disclose information about the IP addressing scheme of the internal network. This information can be used to conduct further attacks.The significance of this finding should be confirmed manually.'
                    imp='N/A'
                    sol='Prevent this information from being displayed to the user.'
                    ref='CWE:200'
                    link='https://www.invicti.com/blog/web-security/information-disclosure-issues-attacks/'

                    head='[INFO] INTERNAL IP DISCLOSURE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #23
                if str(j)=='http-litespeed-sourcecode-download':
                    pass
                    ##DUE

                #24
                if str(j)=='http-ls':
                    pass
                    ##DUE

                #25
                if str(j)=='http-malware-host' and re.search('Host appears to be infected',script,re.IGNORECASE):
                    v_name='Malware Detected'
                    score=9.6
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
                    risk='Critical'
                    desc='Service appears to contain malware'
                    imp='Malware is malicious software that may attempt to install dangerous software on visitor\'s computers to steal or delete personal information. The URL from alert details was marked as malware on at least one malware database.'
                    sol='If your site has been infected with malware, you need to take it offline and identify the malware source. Once you\'ve identified the source of the problem, you should clean up your site and take action to prevent reinfection. Consult Web references for more information.'
                    ref='CWE:506'
                    link='https://transparencyreport.google.com/safe-browsing/search,https://www.yandex.com/safety/,https://cloud.google.com/web-risk/docs/advisory/,https://www.virustotal.com/gui/'

                    head='[CRTIC] POSSIBLE MALWARE FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                #26
                if str(j)=='http-methods' :
                    if re.search('OPTIONS',script,re.IGNORECASE):
                        v_name='OPTIONS Method Enabled'
                        score=0.0
                        strng=''
                        risk='Informational'
                        desc='OPTIONS method is allowed. This issue is reported as extra information.'
                        imp='Information disclosed from this page can be used to gain additional information about the target system.'
                        sol='Disable OPTIONS method in all production systems.'
                        ref='CWE:16'
                        link='https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006),http://www.nessus.org/u?d9c03a9a,http://www.nessus.org/u?b019cbdb'

                        head='[INFO] OPTIONS METHOD ENABLED'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                    if re.search('TRACE',script,re.IGNORECASE):
                        v_name='TRACE Method Enabled'
                        score=5.3
                        strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                        risk='Medium'
                        desc='HTTP TRACE method is enabled on this web server. In the presence of other cross-domain vulnerabilities in web browsers, sensitive header information could be read from any domains that support the HTTP TRACE method.'
                        imp='An attacker can use this information to conduct further attacks.'
                        sol='Disable TRACE method to avoid attackers using it to better exploit other vulnerabilities.'
                        ref='CVE-2003-1567,CVE-2004-2320,CVE-2010-0386,CWE:16,CWE:200,CERT:288308,CERT:867593'
                        link='https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf,http://www.apacheweek.com/issues/03-01-24,https://download.oracle.com/sunalerts/1000718.1.html'

                        head=' [MED] TRACE METHOD ENABLED'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-method-tamper' and re.search('VULNERABLE:',script,re.IGNORECASE):
                    v_name='HTTP Verb Tampering'
                    score=6.5
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
                    risk='Medium'
                    desc='By manipulating the HTTP verb it was possible to bypass the authorization on this directory. The scanner sent a request with a custom HTTP verb (WVS in this case) and managed to bypass the authorization. The attacker can also try any of the valid HTTP verbs, such as HEAD, TRACE, TRACK, PUT, DELETE, and many more.'
                    imp='An application is vulnerable to HTTP Verb tampering if the following conditions hold:\ni) it uses a security control that lists HTTP verbs\nii) the security control fails to block verbs that are not listed\niii) it has GET functionality that is not idempotent or will execute with an arbitrary HTTP verb.'
                    sol='In the case of Apache + .htaccess, don\'t use HTTP verb restrictions or use LimitExcept.Check references for more information on how to fix this problem on other platforms.'
                    ref='CWE:285,CVE-2020-4779'
                    link='https://www.owasp.org/index.php/Testing_for_HTTP_Verb_Tampering_(OTG-INPVAL-003),https://www.imperva.com/learn/application-security/http-verb-tampering/#:~:text=HTTP%20Verb%20Tampering%20is%20an%20attack%20that%20exploits,access%20to%20restricted%20resources%20by%20other%20HTTP%20methods.'

                    head=' [MED] HTTP VERB TAMPERING'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-open-proxy' and re.search('Potentially',script,re.IGNORECASE):
                    v_name='HTTP Open Proxy Detection'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The remote web proxy server accepts requests.'
                    imp='The remote web proxy accepts unauthenticated HTTP requests from the Nessus scanner. By routing requests through the affected proxy, a user may be able to gain some degree of anonymity while browsing websites, which will see requests as originating from the remote host itself rather than the user\'s host.'
                    sol='Make sure access to the proxy is limited to valid users/hosts.'
                    ref=''
                    link=''

                    head='[INFO] HTTP OPEN PROXY DETECTED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-open-redirect' and (re.search('https://',script,re.IGNORECASE) or re.search('http://',script,re.IGNORECASE)):
                    v_name='Open Redirect'
                    score=4.7
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N'
                    risk='Medium'
                    desc='The web application accepts a parameter value that allows redirects to unrestricted locations.'
                    imp='The remote web application contains functionality to redirect to a specific URL. This functionality is not restricted to relative URLs within the application and could be leveraged by an attacker to fool an end user into believing that a malicious URL they were redirected to is valid.'
                    sol='Parameters that are used to dynamically redirect must be restricted to paths within the application. If relative paths are accepted, the base path should be explicitly prepended.'
                    ref='CWE:601,CVE-2020-1323'
                    link='https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/'

                    head=' [MED] OPEN REDIRECTION ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-passwd' and re.search('Directory traversal found',script,re.IGNORECASE):
                    v_name='Directory Traversal'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='Directory traversal (also known as file path traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files. In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.'
                    imp='Directory Traversal is a vulnerability which allows attackers to access restricted directories and read files outside of the web server\'s root directory.'
                    sol='The most effective way to prevent file path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way.If it is considered unavoidable to pass user-supplied input to filesystem APIs, then two layers of defense should be used together to prevent attacks:\n i) The application should validate the user input before processing it. Ideally, the validation should compare against a whitelist of permitted values. If that isn\'t possible for the required functionality, then the validation should verify that the input contains only permitted content, such as purely alphanumeric characters.\n ii) After validating the supplied input, the application should append the input to the base directory and use a platform filesystem API to canonicalize the path. It should verify that the canonicalized path starts with the expected base directory.'
                    ref='CWE:22,CVE-2021-30497'
                    link='https://www.acunetix.com/websitesecurity/directory-traversal/'

                    head=' [MED] DIRECTORY TRAVERSAL'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-phpmyadmin-dir-traversal' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion'
                    score=4.2
                    strng='CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P'
                    risk='Medium'
                    desc='The remote web server contains a PHP application that is prone to a local file inclusion flaw.'
                    imp='The version of phpMyAdmin installed on the remote host allows attackers to read and possibly execute code from arbitrary files on the local host because of its failure to sanitize the parameter \'subform\' before using it in the \'libraries/grab_globals.lib.php\' script.'
                    sol='Upgrade to phpMyAdmin 2.6.4-pl2 or later.'
                    ref='CVE-2005-3299'
                    link='http://securityreason.com/achievement_securityalert/24,http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-4'

                    head=' [MED] PHPMYADMIN LOCAL FILE INCLUSION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-phpself-xss' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Unsafe use of $_SERVER["PHP_SELF"] in PHP files'
                    score=4.3
                    strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N'
                    risk='Medium'
                    desc='PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.'
                    imp=''
                    sol=''
                    ref='CVE-2011-3356,CWE:79'
                    link=''

                    head=' [MED] POSSIBLE PHP_SELF XSS'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-put' and re.search('successfully created',script,re.IGNORECASE):
                    v_name='HTTP PUT Method is Enabled'
                    score=7.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    risk='High'
                    desc='The remote web server allows the PUT method.'
                    imp='The PUT method allows an attacker to upload arbitrary web pages on the server. If the server is configured to support scripts like ASP, JSP, or PHP it will allow the attacker to execute code with the privileges of the web server.The DELETE method allows an attacker to delete arbitrary content from the web server.'
                    sol='Disable the PUT method in the web server configuration.'
                    ref='CVE-2021-35243'
                    link='https://tools.ietf.org/html/rfc7231#section-4.3.4,https://tools.ietf.org/html/rfc7231#section-4.3.5'

                    head=' [MED] HTTP PUT METHOD'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-rfi-spider' :#and re.search('',script):
                    pass
                    ##DUE

                if str(j)=='http-robots.txt' and re.search('disallowed entr',script,re.IGNORECASE):
                    v_name='robots.txt Information Disclosure'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The file robots.txt is used to give instructions to web robots, such as search engine crawlers, about locations within the web site that robots are allowed, or not allowed, to crawl and index.The presence of the robots.txt does not in itself present any kind of security vulnerability. However, it is often used to identify restricted or private areas of a site\'s contents. The information in the file may therefore help an attacker to map out the site\'s contents, especially if some of the locations identified are not linked from elsewhere in the site. If the application relies on robots.txt to protect access to these areas, and does not enforce proper access control over them, then this presents a serious vulnerability.'
                    imp='The remote host contains a file named \'robots.txt\' that is intended to prevent web \'robots\' from visiting certain directories in a website for maintenance or indexing purposes. A malicious user may also be able to use the contents of this file to learn of sensitive documents or directories on the affected site and either retrieve them directly or target them for other attacks.'
                    sol='Review the contents of the site\'s robots.txt file, use Robots META tags instead of entries in the robots.txt file, and/or adjust the web server\'s access controls to limit access to sensitive material.'
                    ref=''
                    link='http://www.robotstxt.org/orig.html'

                    head='[INFO] ROBOTS.TXT FOUND'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-sap-netweaver-leak' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Anonymous Access To SAP Netweaver Portal'
                    score=7.5
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
                    risk='High'
                    desc='SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information including file system structure, LDAP users, emails and other information.'
                    imp='Multiple vulnerabilities may be present in SAP NetWeaver Application Server ABAP, including the following:\n i) SAP Netweaver AS - versions 700, 701, 702, 710, 711, 730, 740, 750, 751, 752, 753, 754, 755, 756 - contain a cross-site scripting vulnerability that allows an unauthenticated attacker to inject code that may expose sensitive data. (CVE-2022-22534).\n ii) SAP NetWeaver AS ABAP (Workplace Server) - versions 700, 701, 702, 731, 740 750, 751, 752, 753, 754, 755, 756, 787 - contain a SQL injection vulnerability that allows an attacker to execute crafted database queries that could expose the backend database. (CVE-2022-22540).\n iii) SAP NetWeaver AS ABAP - versions 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756 - contain an information disclosure vulnerability that aloows an authenticated attacker to read connection details stored with the destination for http calls. (CVE-2022-22545)'
                    sol=''
                    ref='CVE-2022-22545,CVE-2022-22540,CVE-2022-22534'
                    link='https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm'

                    head='[HIGH] ANONYMUS ACCESS TO SAP NETWEAVER PORTAL'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-shellshock' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='HTTP Shellshock Vulnerability'
                    score=9.8
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='This web application might be affected by the vulnerability known as Shellshock. It seems the server is executing commands injected via malicious HTTP headers.'
                    imp='At first, the vulnerability doesn\'t look all that serious. Executing commands is what bash is used for. But in this case, code can be executed without the user\'s intent by setting an environment variable.The most problematic scenario is bash scripts executed via cgi-bin. The CGI specification requires the web server to convert HTTP request headers supplied by the client to environment variables. If a bash script is called via cgi-bin, an attacker may use this to execute code as the web server.'
                    sol='Since the patch is incomplete, you should try to implement additional measures to protect your systems. Various Intrusion Detection System (IDS) and Web Application Firewall (WAF) vendors have released rules to block exploitation. Realize that these rules may be incomplete as well. Many rules I have seen so far just look for the string "() {" which was present in the original proof of concept exploit, but could easily be changed for example by adding more or different white spaces.You could switch your default shell to an alternative like ksh or sh. But this,will likely break existing scripts. Different shells use slightly different syntax.On many embedded systems you may already use an alternative shell ("busybox") that is not vulnerable. Another option to limit the impact of the vulnerability is SELinux, but by default, it does not prevent the initial exploit.'
                    ref='CVE-2014-6271'
                    link='http://www.openwall.com/lists/oss-security/2014/09/24/10,https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169,http://seclists.org/oss-sec/2014/q3/685,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271'

                    head='[CRIT] HTTP SHELLSHOCK VULNERABILTY'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if (str(j)=='http-slowloris-check' or str(j)=='http-slowloris') and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Slowloris DOS Attack'
                    score=7.5
                    risk='High'
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
                    desc='Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.  It accomplishes this by opening connections to the target web server and sending a partial request. By doing so, it starves    the http server\'s resources causing Denial Of Service.'
                    imp='Slowloris is an application layer attack which operates by utilizing partial HTTP requests. The attack functions by opening connections to a targeted Web server and then keeping those connections open as long as it can.\nSlowloris is not a category of attack but is instead a specific attack tool designed to allow a single machine to take down a server without using a lot of bandwidth. Unlike bandwidth-consuming reflection-based DDoS attacks such as NTP amplification, this type of attack uses a low amount of bandwidth, and instead aims to use up server resources with requests that seem slower than normal but otherwise mimic regular traffic. It falls in the category of attacks known as “low and slow” attacks. The targeted server will only have so many threads available to handle concurrent connections. Each server thread will attempt to stay alive while waiting for the slow request to complete, which never occurs. When the server’s maximum possible connections has been exceeded, each additional connection will not be answered and denial-of-service will occur.\nA Slowloris attack occurs in 4 steps: \n i) The attacker first opens multiple connections to the targeted server by sending multiple partial HTTP request headers.\n ii) The target opens a thread for each incoming request, with the intent of closing the thread once the connection is completed. In order to be efficient, if a connection takes too long, the server will timeout the exceedingly long connection, freeing the thread up for the next request.\n iii) To prevent the target from timing out the connections, the attacker periodically sends partial request headers to the target in order to keep the request alive. In essence saying, “I’m still here! I’m just slow, please wait for me.”\n iv) The targeted server is never able to release any of the open partial connections while waiting for the termination of the request. Once all available threads are in use, the server will be unable to respond to additional requests made from regular traffic, resulting in denial-of-service.\nThe key behind a Slowloris is its ability to cause a lot of trouble with very little bandwidth consumption.'
                    sol='For web servers that are vulnerable to Slowloris, there are ways to mitigate some of the impact. Mitigation options for vulnerable servers can be broken down into 3 general categories:\nIncrease server availability - Increasing the maximum number of clients the server will allow at any one time will increase the number of connections the attacker must make before they can overload the server. Realistically, an attacker may scale the number of attacks to overcome server capacity regardless of increases.\nRate limit incoming requests - Restricting access based on certain usage factors will help mitigate a Slowloris attack. Techniques such as limiting the maximum number of connections a single IP address is allowed to make, restricting slow transfer speeds, and limiting the maximum time a client is allowed to stay connected are all approaches for limiting the effectiveness of low and slow attacks.\nCloud-based protection - Use a service that can function as a reverse proxy, protecting the origin server.'
                    ref='CVE-2018-12122,CVE-2007-6750'
                    link='http://ha.ckers.org/slowloris/,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750'

                    head='[HIGH] SLOWLORIS DOS ATTACK'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-sql-injection' and re.search('Possible sqli',script,re.IGNORECASE):
                    v_name='SQL Injection'
                    score=10.0
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N'
                    risk='Critical'
                    desc='SQL injection (SQLi) refers to an injection attack wherein an attacker can execute malicious SQL statements that control a web application\'s database server.SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application\'s content or behavior.\nIn some situations, an attacker can escalate an SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a denial-of-service attack'
                    imp='A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. Many high-profile data breaches in recent years have been the result of SQL injection attacks, leading to reputational damage and regulatory fines. In some cases, an attacker can obtain a persistent backdoor into an organization\'s systems, leading to a long-term compromise that can go unnoticed for an extended period.'
                    sol='Use parameterized queries when dealing with SQL queries that contain user input. Parameterized queries allow the database to understand which parts of the SQL query should be considered as user input, therefore solving SQL injection.'
                    ref='CWE:89,CVE-2022-26201,CVE-2022-24646,CVE-2022-24707,CVE-2022-25506,CVE-2022-25404, CVE-2022-25394'
                    link='https://www.acunetix.com/websitesecurity/sql-injection/,https://www.acunetix.com/websitesecurity/sql-injection2/,https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/,https://www.owasp.org/index.php/SQL_Injection,http://pentestmonkey.net/category/cheat-sheet/sql-injection'

                    head='[HIGH] SQL INJECTION VULNERABILTY'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-trace' and re.search('is enabled',script,re.IGNORECASE):
                    v_name='TRACE Method Enabled'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='HTTP TRACE method is enabled on this web server. In the presence of other cross-domain vulnerabilities in web browsers, sensitive header information could be read from any domains that support the HTTP TRACE method.'
                    imp='An attacker can use this information to conduct further attacks.'
                    sol='Disable TRACE method to avoid attackers using it to better exploit other vulnerabilities.'
                    ref='CVE-2003-1567,CVE-2004-2320,CVE-2010-0386,CWE:16,CWE:200,CERT:288308,CERT:867593'
                    link='https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf,http://www.apacheweek.com/issues/03-01-24,https://download.oracle.com/sunalerts/1000718.1.html'

                    head=' [MED] TRACE METHOD ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-traceroute' and len(script)>10:
                    v_name='Traceroute Information'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='It was possible to obtain traceroute information.'
                    imp='Makes a traceroute to the remote host.'
                    sol='N/A'
                    ref=''
                    link=''

                    head='[INFO] TRACEROUTE INFORMATION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-userdir-enum' and re.search('Potential Users',script,re.IGNORECASE):
                    pass
                    ##DUE

                if str(j)=='http-vmware-path-vuln' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='VMWARE Path Traversal'
                    score=5.0
                    strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
                    risk='Medium'
                    desc='Directory traversal vulnerability in VMware Server 1.x before 1.0.10 build 203137 and 2.x before 2.0.2 build 203138 on Linux, VMware ESXi 3.5, and VMware ESX 3.0.3 and 3.5 allows remote attackers to read arbitrary files via unspecified vectors.'
                    imp='VMware is a set of server-emulation applications available for several platforms.Multiple VMware products are prone to a directory-traversal vulnerability because they fail to sufficiently sanitize user-supplied input. Attackers on the same subnetwork may use a specially crafted request to retrieve arbitrary files from the host operating system.A remote attacker could exploit the vulnerability using directory-traversal characters to access arbitrary files that contain sensitive information that could aid in further attacks.\nAffected :\n\t1.VMWare Server 2.0.1 build 156745\n\t2.VMWare Server 2.0.1\n\t3.VMWare Server 1.0.9 build 156507\n\t4.VMWare Server 1.0.9\n\t5.VMWare Server 1.0.8 build 126538\n\t6.VMWare Server 1.0.8\n\t7.VMWare Server 1.0.7 build 108231\n\t7.VMWare Server 1.0.7\n\t8.VMWare Server 1.0.6 build 91891\n\t9.VMWare Server 1.0.6\n\t10.VMWare Server 1.0.5 Build 80187\n\t11.VMWare Server 1.0.5\n\t12.VMWare Server 1.0.4\n\t13.VMWare Server 1.0.3\n\t14.VMWare Server 1.0.2\n\t15.VMWare Server 2.0\n\t16.VMWare ESXi Server 3.5 ESXe350-20090440\n\t17.VMWare ESXi Server 3.5\n\t18.VMWare ESX Server 3.0.3\n\t19.VMWare ESX Server 3.0.3\n\t20.VMWare ESX Server 3.5 ESX350-200906407\n\t21.VMWare ESX Server 3.5 ESX350-200904401\n\t22.VMWare ESX Server 3.5'
                    sol='Use Non-Vulnerable Packages:\n\t1.VMWare Workstation 6.0.3\n\t2.VMWare Workstation 5.5.6\n\t3.VMWare Player 2.0.3\n\t4.VMWare Player 1.0.5\n\t5.VMWare ACE 2.0.3\n\t6.VMWare ACE 1.0.5\n\t7.VMWare ESX\n\t8.VMWare Server'
                    ref='CVE-2009-3733'
                    link='http://www.securityfocus.com/bid/36842,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3733'

                    head=' [MED] VMWARE PATH TRAVERSAL'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-vuln-misfortune-cookie' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Allegro RomPager 4.07 < 4.34 Multiple Vulnerabilities (Misfortune Cookie)'
                    score=9.8
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='The cookie handling routines in RomPager 4.07 are vulnerable to remote code execution. This script has verified the vulnerability by exploiting the web server in a safe manner.'
                    imp='Versions of RomPager 4.07 and prior to 4.34 are potentially affected by multiple issues :\n\t- A buffer overflow vulnerability exists because the RomPager web server fails to perform adequate bounds checks on user-supplied input. Attackers can exploit this issue to execute arbitrary code with the privileged access of RomPager.(CVE-2014-9223)\n\t- A security bypass vulnerability exists due to an error within the HTTP cookie management mechanism (aka, the \'Misfortune Cookie\' issue) which could allow any user to determine the \'fortune\' of a request by manipulating cookies. An attacker can exploit this issue to corrupt memory and alter the application state by sending specially crafted HTTP cookies. This could be exploited to gain the administrative privileges for the current session by tricking the attacked device. (CVE-2014-9222)'
                    sol='Contact the vendor for an updated firmware image. Allegro addressed both issues in mid-2005 with RomPager version 4.34.'
                    ref='CVE-2014-9222,CVE-2014-9223,CWE:119,CWE:17'
                    link='http://mis.fortunecook.ie/,http://www.nessus.org/u?e6bf690f,http://www.nessus.org/u?22cba06d,http://www.kb.cert.org/vuls/id/561444'

                    head='[CRTIC] ROMPAGER - MISFORTUNE COOKIE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='http-vuln-wnr1000-creds' and re.search('VULNERABLE',script,re.IGNORECASE):
                #v_name='Netgear WNR1000v3 Credential Harvesting'
                    pass
                    ##DUE

                if str(j)=='http-webdav-scan':
                    pass
                    ##DUE

                if str(j)=='http-xssed' and re.search('found the following previously reported XSS',script,re.IGNORECASE):
                    v_name='Cross-Site Scripting(XSS)'
                    score=6.1
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                    risk='Medium'
                    desc='Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user\'s data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application\'s functionality and data.'
                    imp='Cross-site Scripting (XSS) refers to client-side code injection attack wherein an attacker can execute malicious scripts into a legitimate website or web application. XSS occurs when a web application makes use of unvalidated or unencoded user input within the output it generates.\nThere are three main types of XSS attacks. These are:\n\tReflected XSS, where the malicious script comes from the current HTTP request.\n\tStored XSS, where the malicious script comes from the website\'s database.\n\tDOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.\nThe actual impact of an XSS attack generally depends on the nature of the application, its functionality and data, and the status of the compromised user. For example:\nIn a brochureware application, where all users are anonymous and all information is public, the impact will often be minimal.\nIn an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.\nIf the compromised user has elevated privileges within the application, then the impact will generally be critical, allowing the attacker to take full control of the vulnerable application and compromise all users and their data.'
                    sol='Preventing cross-site scripting is trivial in some cases but can be much harder depending on the complexity of the application and the ways it handles user-controllable data.In general, effectively preventing XSS vulnerabilities is likely to involve a combination of the following measures:\nFilter input on arrival. At the point where user input is received, filter as strictly as possible based on what is expected or valid input.\nEncode data on output. At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.\nUse appropriate response headers. To prevent XSS in HTTP responses that aren\'t intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.\nContent Security Policy. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.'
                    ref='CWE:79,CVE-2020-10385'
                    link='http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting,https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet'

                    head=' [MED] CROSS-SITE SCRIPTING'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ip-https-discover':
                    pass
                    ##DUE

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: S Q L:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

                if str(j)=='ms-sql-empty-password' and re.search('success',script,re.IGNORECASE):
                    v_name='MySQL Unpassworded Account Check'
                    score=7.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    risk='High'
                    desc='The remote database server can be accessed without a password.'
                    imp='It is possible to connect to the remote MySQL database server using an unpassworded account. This may allow an attacker to launch further attacks against the database.'
                    sol='Disable or set a password for the affected account.'
                    ref='CVE-2002-1809, CVE-2004-1532'
                    link='https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html'

                    head='[HIGH] MYSQL UNCREDENTIAL CHECK'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='mysql-empty-password' and re.search('has empty password',script,re.IGNORECASE):
                    v_name='MySQL Unpassworded Account Check'
                    score=7.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    risk='High'
                    desc='The remote database server can be accessed without a password.'
                    imp='It is possible to connect to the remote MySQL database server using an unpassworded account. This may allow an attacker to launch further attacks against the database.'
                    sol='Disable or set a password for the affected account.'
                    ref='CVE-2002-1809, CVE-2004-1532'
                    link='https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html'

                    head='[HIGH] MYSQL UNCREDENTIAL CHECK'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ms-sql-xp-cmdshell' and re.search('output',script,re.IGNORECASE):
                    v_name='MS12-048: Vulnerability in Windows Shell Could Allow Remote Code Execution'
                    score=9.3
                    strng='CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C'
                    risk='High'
                    desc='A remote code execution vulnerability exists in the way Windows handles file and directory names.'
                    imp='By tricking a user into opening a file or directory with a specially crafted name, an attacker could exploit this vulnerability to execute arbitrary code on the remote host subject to the privileges of the user.'
                    sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                    ref='CVE-2012-0175'
                    link='https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-048'
                    head='[HIGH] MS12-048:MS-SQL RCE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: S M B :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

                if str(j)=='smb2-security-mode' and not re.search('Message signing enabled but not required',script,re.IGNORECASE):
                    v_name='SMB Signing not required'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'
                    risk='Medium'
                    desc='Signing is not required on the remote SMB server.'
                    imp='Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.'
                    sol='Enforce message signing in the host\'s configuration. On Windows, this is found in the policy setting \'Microsoft network server: Digitally sign communications (always)\'. On Samba, the setting is called \'server signing\'.'
                    ref=''
                    link='http://www.nessus.org/u?df39b8b3,http://technet.microsoft.com/en-us/library/cc731957.aspx,http://www.nessus.org/u?74b80723,https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html,http://www.nessus.org/u?a3cac4ea'

                    head=' [MED] SMB SIGN-IN NOT REQUIRED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb2-vuln-uptime' and not re.search('vulnerable',script,re.IGNORECASE):
                    v_name='MS17-010: Security Update for Microsoft Windows SMB Server : ETERNALBLUE / ETERNALCHAMPION / ETERNALROMANCE / ETERNALSYNERGY / WannaCry / EternalRocks / Petya / uncredentialed check'
                    score=8.1
                    strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='High'
                    desc='The remote Windows host is affected by multiple vulnerabilities.'
                    imp='The remote Windows host is affected by the following vulnerabilities :\n\t- Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted packet, to execute arbitrary code. (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0148)\n\t- An information disclosure vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of certain requests. An unauthenticated, remote attacker can exploit this, via a specially crafted packet, to disclose sensitive information. (CVE-2017-0147)\n\tETERNALBLUE, ETERNALCHAMPION, ETERNALROMANCE, and ETERNALSYNERGY are four of multiple Equation Group vulnerabilities and exploits disclosed on 2017/04/14 by a group known as the Shadow Brokers. WannaCry / WannaCrypt is a ransomware program utilizing the ETERNALBLUE exploit, and EternalRocks is a worm that utilizes seven Equation Group vulnerabilities. Petya is a ransomware program that first utilizes CVE-2017-0199, a vulnerability in Microsoft Office, and then spreads via ETERNALBLUE.'
                    sol='Microsoft has released a set of patches for Windows Vista, 2008, 7, 2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. Microsoft has also released emergency patches for Windows operating systems that are no longer supported, including Windows XP, 2003, and 8.\nFor unsupported Windows operating systems, e.g. Windows XP, Microsoft recommends that users discontinue the use of SMBv1. SMBv1 lacks security features that were included in later SMB versions. SMBv1 can be disabled by following the vendor instructions provided in Microsoft KB2696547. Additionally, US-CERT recommends that users block SMB directly by blocking TCP port 445 on all network boundary devices. For SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary devices'
                    ref='CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148'
                    link='http://www.nessus.org/u?68fc8eff,http://www.nessus.org/u?321523eb,http://www.nessus.org/u?065561d0,http://www.nessus.org/u?d9f569cf,https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/,http://www.nessus.org/u?b9d9ebf9,http://www.nessus.org/u?8dcab5e4,http://www.nessus.org/u?234f8ef8,http://www.nessus.org/u?4c7e0cf3,https://github.com/stamparm/EternalRocks/,http://www.nessus.org/u?59db5b5b'

                    head='[HIGH] MS17-010: SECURITY FOR MS WINDOWS SMB SERVER'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb-double-pulsar-backdoor' and not re.search('vulnerable',script,re.IGNORECASE):
                    v_name='SMB Server DOUBLEPULSAR Backdoor / Implant Detection (EternalRocks)'
                    score=8.1
                    strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='High'
                    desc='A backdoor exists on the remote Windows host.'
                    imp='DOUBLEPULSAR is one of multiple Equation Group SMB implants and backdoors disclosed on 2017/04/14 by a group known as the Shadow Brokers. The implant allows an unauthenticated, remote attacker to use SMB as a covert channel to exfiltrate data, launch remote commands, or execute arbitrary code.\nEternalRocks is a worm that propagates by utilizing DOUBLEPULSAR.'
                    sol='Remove the DOUBLEPULSAR backdoor / implant and disable SMBv1.'
                    ref='CVE-2017-0144'
                    link='http://www.nessus.org/u?43ec89df,https://github.com/countercept/doublepulsar-detection-script,https://github.com/stamparm/EternalRocks/,http://www.nessus.org/u?68fc8eff'

                    head='[HIGH] SMB DOUBLEPULSAR BACKDOOR'
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb-os-discovery':
                    pass
                    ##DUE

                if str(j)=='smb-protocols' and re.search('SMBv1',script,re.IGNORECASE):
                    v_name='Server Message Block (SMB) Protocol Version 1 Enabled'
                    score=0.0
                    strng=''
                    risk='Informational'
                    desc='The remote Windows host supports the SMBv1 protocol.'
                    imp='The remote Windows host supports Server Message Block Protocol version 1 (SMBv1). Microsoft recommends that users discontinue the use of SMBv1 due to the lack of security features that were included in later SMB versions. Additionally, the Shadow Brokers group reportedly has an exploit that affects SMB; however, it is unknown if the exploit affects SMBv1 or another version. In response to this, US-CERT recommends that users disable SMBv1 per SMB best practices to mitigate these potential issues.'
                    sol='Disable SMBv1 according to the vendor instructions in Microsoft KB2696547. Additionally, block SMB directly by blocking TCP port 445 on all network boundary devices. For SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary devices.'
                    ref=''
                    link='https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/,https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and,http://www.nessus.org/u?8dcab5e4,http://www.nessus.org/u?234f8ef8,http://www.nessus.org/u?4c7e0cf3'

                    head='[INFO] SMBv1 ENABLED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb-protocols' and re.search('SMBv1',script,re.IGNORECASE):
                    v_name='Microsoft Windows SMBv1 Multiple Vulnerabilities'
                    score=8.1
                    strng='CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='High'
                    desc='The remote Windows host supports the SMBv1 protocol.'
                    imp='The remote Windows host has Microsoft Server Message Block 1.0 (SMBv1) enabled. It is, therefore, affected by multiple vulnerabilities :\n\t- Multiple information disclosure vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to disclose sensitive information. (CVE-2017-0267, CVE-2017-0268, CVE-2017-0270, CVE-2017-0271, CVE-2017-0274, CVE-2017-0275, CVE-2017-0276)\n\t- Multiple denial of service vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of requests. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMB request, to cause the system to stop responding. (CVE-2017-0269, CVE-2017-0273, CVE-2017-0280)\n\t- Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to execute arbitrary code. (CVE-2017-0272, CVE-2017-0277, CVE-2017-0278, CVE-2017-0279)'
                    sol='Apply the applicable security update for your Windows version :\n\t- Windows Server 2008 : KB4018466\n\t- Windows 7 : KB4019264\n\t- Windows Server 2008 R2 : KB4019264\n\t- Windows Server 2012 : KB4019216\n\t- Windows 8.1 / RT 8.1. : KB4019215\n\t- Windows Server 2012 R2 : KB4019215\n\t- Windows 10 : KB4019474\n\t- Windows 10 Version 1511 : KB4019473\n\t- Windows 10 Version 1607 : KB4019472\n\t- Windows 10 Version 1703 : KB4016871\n\t- Windows Server 2016 : KB4019472'
                    ref='CVE-2017-0267, CVE-2017-0268, CVE-2017-0269, CVE-2017-0270, CVE-2017-0271, CVE-2017-0272, CVE-2017-0273, CVE-2017-0274, CVE-2017-0275, CVE-2017-0276, CVE-2017-0277, CVE-2017-0278, CVE-2017-0279, CVE-2017-0280'
                    link='http://www.nessus.org/u?c21268d4,http://www.nessus.org/u?b9253982,http://www.nessus.org/u?23802c83,http://www.nessus.org/u?8313bb60,http://www.nessus.org/u?7677c678,http://www.nessus.org/u?36da236c,http://www.nessus.org/u?0981b934,http://www.nessus.org/u?c88efefa,http://www.nessus.org/u?695bf5cc,http://www.nessus.org/u?459a1e8c,http://www.nessus.org/u?ea45bbc5,http://www.nessus.org/u?4195776a,http://www.nessus.org/u?fbf092cf,http://www.nessus.org/u?8c0cc566'

                    head='[HIGH] SMBv1 MULTIPLE VULNERABILITY'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb-vuln-conficker' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Conficker Worm Detection (uncredentialed check)'
                    score=10.0
                    strng='CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
                    risk='Critical'
                    desc='The remote host seems to be infected by a variant of the Conficker worm.'
                    imp='The remote host seems to be infected by the Conficker worm. This worm has several capabilities which allow an attacker to execute arbitrary code on the remote operating system. The remote host might also be attempting to propagate the worm to third party hosts.'
                    sol='Update your Antivirus and perform a full scan of the remote operating system.'
                    ref=''
                    link='http://net.cs.uni-bonn.de/wg/cs/applications/containing-conficker/,https://support.microsoft.com/en-us/help/962007/virus-alert-about-the-win32-conficker-worm,http://www.nessus.org/u?1f3900d3'

                    head='[CRIT] CONFICKER WORM DETECTED'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='smb-vuln-regsvc-dos' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Service regsvc in Microsoft Windows systems vulnerable to denial of service'
                    score=7.8
                    strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C'
                    risk='High'
                    desc='The remote Windows host has a denial of service vulnerability.'
                    imp='A vulnerability in the SMB service on the remote Windows host can reportedly be abused by a remote, unauthenticated attacker to cause the host to stop responding until manually restarted.'
                    sol='Microsoft has released a set of patches for Vista, 2008, 7, and 2008 R2.'
                    ref='CVE-2011-1267'
                    link='https://www.nessus.org/u?beda7c4d'

                    head='[HIGH] SMB DOS VULNERABILITY'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)


                if str(j)=='smb-vuln-webexec' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='Remote Code Execution vulnerability in WebExService'
                    score=7.8
                    strng='CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    risk='High'
                    desc='A remote code execution vulnerability exists in WebExService (WebExec).'
                    imp='A vulnerability in the update service of Cisco Webex Meetings Desktop App for Windows could allow an authenticated, local attacker to execute arbitrary commands as a privileged user. The vulnerability is due to insufficient validation of user-supplied parameters. An attacker could exploit this vulnerability by invoking the update service command with a crafted argument. An exploit could allow the attacker to run arbitrary commands with SYSTEM user privileges. While the CVSS Attack Vector metric denotes the requirement for an attacker to have local access, administrators should be aware that in Active Directory deployments, the vulnerability could be exploited remotely by leveraging the operating system remote management tools.'
                    sol=''
                    ref='CVE-2018-15442'
                    link='http://www.securityfocus.com/bid/105734,http://www.securitytracker.com/id/1041942'

                    head='[HIGH] SWEBEXSERVICE REMOTE CODE EXECUTION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: R P C :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

                if str(j)=='realvnc-auth-bypass' and re.search('VULNERABLE',script,re.IGNORECASE):
                    v_name='RealVNC 4.1.0 - 4.1.1 Authentication Bypass'
                    score=7.5
                    strng='CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
                    risk='High'
                    desc='RealVNC 4.1.1, and other products that use RealVNC such as AdderLink IP, allows remote attackers to bypass authentication via a request in which the client specifies an insecure security type such as "Type 1 - None", which is accepted even if it is not offered by the server, as originally demonstrated using a long password.'
                    imp='RealVNC is susceptible to an authentication-bypass vulnerability. A malicious VNC client can cause a VNC server to allow it to connect without any authentication regardless of the authentication settings configured in the server. Exploiting this issue allows attackers to gain unauthenticated, remote access to the VNC servers.'
                    sol='Update the affected package.'
                    ref='CVE-2006-2369,CWE-287'
                    link='http://www.intelliadmin.com/index.php/2006/05/security-flaw-in-realvnc-411/,https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2369'

                    head='[HIGH] RealVNC AUTH BYPASS'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='rdp-vuln-ms12-020' and re.search('VULNERABLE',script,re.IGNORECASE):
                    if re.search('Denial Of Service',script,re.IGNORECASE):
                        v_name='MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability'
                        score=4.2
                        strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P'
                        risk='Medium'
                        desc='Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.'
                        imp='A DDoS attack means that it is administered with the same target from different sources – and here the Internet of Things must feel for hackers a bit like a toyshop would to children: millions of devices, all too often unprotected and unmonitored for long periods of time. The scale in which these attacks are now possible is rising tremendously with the advancement of the Internet of Things.'
                        sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                        ref='CVE-2012-0152'
                        link='http://technet.microsoft.com/en-us/security/bulletin/ms12-020,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-015'

                        head=' [MED] RDP DOS ATTACK (MS12-020)'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)
                  
                    if re.search('Remote Code Execution',script,re.IGNORECASE):
                        v_name='MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability'
                        score=4.2
                        strng='CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P'
                        risk='Medium'
                        desc='Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.'
                        imp='An arbitrary remote code vulnerability exists in the implementation of the Remote Desktop Protocol (RDP) on the remote Windows host. The vulnerability is due to the way that RDP accesses an object in memory that has been improperly initialized or has been deleted.If RDP has been enabled on the affected system, an unauthenticated, remote attacker could leverage this vulnerability to cause the system to execute arbitrary code by sending a sequence of specially crafted RDP packets to it.'
                        sol='Microsoft has released a set of patches for Windows XP, 2003, Vista, 2008, 7, and 2008 R2.'
                        ref='CVE-2012-0002'
                        link='http://technet.microsoft.com/en-us/security/bulletin/ms12-020,http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002'

                        head=' [MED] RDP RCE ATTACK (MS12-020)'
                        display('[PORT:'+str(port)+']\t'+head)
                        result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: N F S :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

                if str(j)=='nfs-showmount' and re.search('Telnet server supports encryption',script,re.IGNORECASE):
                    v_name='NFS Share User Mountable'
                    score=7.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
                    risk='High'
                    desc='to access sensitive information from remote NFS shares without having root privileges.'
                    imp='NFS shares exported by the remote server or disclose potentially sensitive information such as a directory listing. An attacker may exploit this issue to gain read and possibly write access to files on remote host, that root privileges were not required to mount the remote shares since the source port to mount the shares was higher than 1024.'
                    sol='Configure NFS on the remote host so that only authorized hosts can mount the remote shares. The remote NFS server should prevent mount requests originating from a non-privileged port.'
                    ref='CVE-1999-0554'
                    link='https://support.datafabric.hpe.com/s/article/NFS-Security-Vulnerability-CVE-1999-0554?language=en_US'

                    head=' [HIGH] NFS MOUNTABLE'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: F T P :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

                if str(j)=='ftp-anon' and re.search('login allowed',script,re.IGNORECASE):
                    v_name='Anonymous FTP Login Enabled'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='Anonymous logins are allowed on the remote FTP server.'
                    imp='The FTP server running on the remote host allows anonymous logins. Therefore, any remote user may connect and authenticate to the server without providing a password or unique credentials. This allows the user to access any files made available by the FTP server.'
                    sol='Disable anonymous FTP if it is not required. Routinely check the FTP server to ensure that sensitive content is not being made available.'
                    ref='CVE-1999-0497'
                    link=''

                    head=' [MED] ANONYMOUS FTP LOGIN'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ftp-bounce' and re.search('bounce',script,re.IGNORECASE):
                    v_name='FTP Bounce Attack'
                    score=5
                    strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
                    risk='Medium'
                    desc='The remote FTP server is prone to a denial of service attack.'
                    imp='The NETFile FTP/Web server on the remote host is vulnerable to a denial of service attack due to its support of the FXP protocol and its failure to validate the IP address supplied in a PORT command.Additionally, this issue can be leveraged to bypass firewall rules to connect to arbitrary hosts.'
                    sol='Upgrade to NETFile FTP/Web Server 7.6.0 or later and disable FXP support.'
                    ref='CVE-2005-1646'
                    link='http://www.security.org.sg/vuln/netfileftp746port.html'

                    head=' [MED] FTP BOUNCE ATTACK'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ftp-libopie' and re.search('vulnerable',script,re.IGNORECASE):
                    v_name='OPIE off-by-one stack overflow'
                    score=4.4
                    strng='CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P'
                    risk='Medium'
                    desc='The remote host is missing one or more security-related updates.'
                    imp='A programming error in the OPIE library could allow an off-by-one buffer overflow to write a single zero byte beyond the end of an on-stack buffer.'
                    sol='Update the affected packages.'
                    ref=''
                    link='http://www.nessus.org/u?8197ddf8'

                    head=' [MED] OPIE OFF_BY_ONE STACK-OVERFLOW'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ftp-proftpd-backdoor' and re.search('backdoored',script,re.IGNORECASE):
                    v_name='FTP Server Backdoor Detection'
                    score=9.8
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='The remote FTP server has a backdoor.'
                    imp='There is a backdoor in the old FTP daemons of Linux that allows remote users to log in as \'NULL\' with password \'NULL\'. These credentials provide root access.'
                    sol='Upgrade your FTP server to the latest version.'
                    ref='CVE-1999-0452'
                    link='http://www.nessus.org/u?8197ddf8'

                    head='[CRIT] FTP BACKDOOR DETECTION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='ftp-vsftpd-backdoor' and re.search('vulnerable',script,re.IGNORECASE):
                    v_name='vsFTPd version 2.3.4 backdoor'
                    score=9.8
                    strng='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    risk='Critical'
                    desc='The remote FTP server has a backdoor.'
                    imp='vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp'
                    sol='Upgrade your FTP server to the latest version.'
                    ref='CVE-2011-2523,CWE-78'
                    link='http://www.nessus.org/u?8197ddf8'

                    head='[CRIT] VSFTPD BACKDOOR DETECTION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: D N S :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                if str(j)=='dns-cache-snoop' and re.search('are cached',script,re.IGNORECASE):
                    v_name='DNS Server Cache Snooping'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='The remote DNS server responds to queries for third-party domains that do not have the recursion bit set.'
                    imp='This may allow a remote attacker to determine which domains have recently been resolved via this name server, and therefore which hosts have been recently visited.For instance, if an attacker was interested in whether your company utilizes the online services of a particular financial institution, they would be able to use this attack to build a statistical model regarding company usage of that financial institution. Of course, the attack can also be used to find B2B partners, web-surfing patterns, external mail servers, and more.\nNote: If this is an internal DNS server not accessible to outside networks, attacks would be limited to the internal network. This may include employees, consultants and potentially users on a guest network or WiFi connection if supported.'
                    sol='Contact the vendor of the DNS software for a fix.'
                    ref=''
                    link='http://cs.unc.edu/~fabian/course_papers/cache_snooping.pdf'

                    head=' [MED] DNS CACHE SNOOPING'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='dns-check-zone' and re.search('pass',script,re.IGNORECASE):               
                    v_name='DNS Server Zone Transfer Allowed'
                    score=5.3
                    strng='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    risk='Medium'
                    desc='The remote DNS server allows zone transfers.'
                    imp='A successful zone transfer was just observed. An attacker may use the zone information to discover sensitive information about hosts on your network.'
                    sol='Verify that you only allow zone transfers to authorized hosts.'
                    ref=''
                    link='http://www.nessus.org/u?08f00b71'

                    head=' [MED] DNS ZONE TRANSFER'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)

                if str(j)=='dns-recursion' and re.search('enabled',script,re.IGNORECASE):                
                    v_name='DNS Server Recursion Enabled'
                    score=5.0
                    strng='CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
                    risk='Medium'
                    desc='The remote DNS server allows zone transfers.'
                    imp='If this is your internal nameserver, then the attack vector may be limited to employees or guest access if allowed.\nIf you are probing a remote nameserver, then it allows anyone to use it to resolve third party names.\nThis allows attackers to perform cache poisoning attacks against this nameserver.\nIf the host allows these recursive queries via UDP, then the host can be used to \'bounce\' Denial of Service attacks against another network or system'
                    sol='Restrict recursive queries to the hosts that should use this nameserver (such as those of the LAN connected to it).If you are using bind 8, you can do this by using the instruction \'allow-recursion\' in the \'options\' section of your named.conf.If you are using bind 9, you can define a grouping of internal addresses using the \'acl\' command.Then, within the options block, you can explicitly state:\'allow-recursion { hosts_defined_in_acl }\'If you are using another name server, consult its documentation.'
                    ref='CVE-1999-0024'
                    link='http://www.nessus.org/u?c4dcf24a'

                    head=' [MED] DNS RECURSION'
                    display('[PORT:'+str(port)+']\t'+head)
                    result[head]=set_data(v_name,score,strng,risk,desc,imp,sol,ref,link,port,script,name)








#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
def ssh(host):
    scripts=['sshv1.nse','ssh2-enum-algos.nse','ssh-hostkey.nse','ssh-publickey-acceptance.nse','ssh-auth-methods.nse']
    #res=_scan(host,'-sV --script='+str(",".join(map(str,scripts)))+' --script-args="userdb=users.lst, passdb=pass.lst, ssh-brute.timeout=4s,ssh_hostkey=all, ssh-run.cmd=ls , ssh-run.username=admin, ssh-run.password=password,ssh.usernames={\'root\', \'user\'}, publickeys={\'./id_rsa1.pub\', \'./id_rsa2.pub\'},ssh.privatekeys={\'./id_rsa1\', \'./id_rsa2\'},ssh.user=\'root\'"')
    #return (filter_data(res))
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s+' --script-args="userdb=users.lst, passdb=pass.lst, ssh-brute.timeout=4s,ssh_hostkey=all, ssh-run.cmd=ls , ssh-run.username=admin, ssh-run.password=password,ssh.usernames={\'root\', \'user\'}, publickeys={\'./id_rsa1.pub\', \'./id_rsa2.pub\'},ssh.privatekeys={\'./id_rsa1\', \'./id_rsa2\'},ssh.user=\'root\'"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def ssl(host):
    scripts=['ssl-enum-ciphers','ssl-ccs-injection.nse','ssl-cert-intaddr.nse','ssl-cert.nse','ssl-date.nse','ssl-dh-params.nse','ssl-known-key.nse','ssl-heartbleed.nse','ssl-poodle.nse','sslv2-drown.nse','sslv2.nse','tls-ticketbleed.nse']
    #res=_scan(host,'-sV --script='+str(",".join(map(str,scripts))))
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def smtp(host):
    scripts=['smtp-commands.nse','smtp-strangeport.nse','smtp-open-relay.nse']
    #res=_scan(host,'-sV --script='+str(",".join(map(str,scripts)))+' --script-args="smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1"')
    #return (filter_data(res))
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s+' --script-args="smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def http(host):
    scripts=['http-apache-negotiation.nse','http-avaya-ipoffice-users.nse','http-awstatstotals-exec.nse','http-brute.nse','http-comments-displayer.nse','http-config-backup.nse','http-cookie-flags','http-cors','http-cross-domain-policy.nse','http-csrf.nse','http-dombased-xss.nse','http-fileupload-exploiter.nse','http-frontpage-login.nse','http-git.nse','http-gitweb-projects-enum.nse','http-google-malware.nse','http-huawei-hg5xx-vuln.nse','http-iis-short-name-brute.nse','http-iis-webdav-vuln.nse','http-internal-ip-disclosure.nse','http-litespeed-sourcecode-download.nse','http-ls.nse','http-malware-host.nse','http-methods.nse','http-method-tamper.nse','http-open-proxy.nse','http-open-redirect.nse','http-passwd.nse','http-phpmyadmin-dir-traversal.nse','http-phpself-xss.nse','http-put','http-rfi-spider.nse','http-robots.txt.nse','http-shellshock.nse','http-slowloris-check.nse','http-sql-injection.nse','http-trace.nse','http-traceroute.nse','http-userdir-enum.nse','http-vmware-path-vuln.nse','http-vuln-misfortune-cookie.nse','http-vuln-wnr1000-creds.nse','http-webdav-scan.nse','http-xssed.nse','ip-https-discover.nse']
    #res=_scan(host,'-sV --script='+str(",".join(map(str,scripts)))+' --script-args="basepath=/cf/adminapi/, basepath=/cf/, http-aspnet-debug.path=/path,http-awstatstotals-exec.cmd=uname, http-awstatstotals-exec.uri=/awstats/index.php, http-cross-domain-policy.domain-lookup=true, http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\',http-put.url=\'/uploads/rootme.php\', http-put.file=\'/tmp/rootme.php\', uri=/cgi-bin/bin, cmd=ls" -F')
    #return (filter_data(res))
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s+' --script-args="basepath=/cf/adminapi/, basepath=/cf/, http-aspnet-debug.path=/path,http-awstatstotals-exec.cmd=uname, http-awstatstotals-exec.uri=/awstats/index.php, http-cross-domain-policy.domain-lookup=true, http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\',http-put.url=\'/uploads/rootme.php\', http-put.file=\'/tmp/rootme.php\', uri=/cgi-bin/bin, cmd=ls"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def sql(host):
    scripts=['ms-sql-empty-password.nse','mysql-empty-password.nse','ms-sql-xp-cmdshell.nse','ms-sql-hasdbaccess.nse']
    #res=_scan(host,'-sV --script='+str(",".join(map(str,scripts)))+' --script-args="smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1"')
    #return (filter_data(res))
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s+' --script-args="mssql.instance-all,mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd=ipconfig"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def smb(host):
    scripts=['smb2-security-mode.nse','smb-security-mode.nse','smb2-vuln-uptime.nse','smb-double-pulsar-backdoor.nse' ,'smb-os-discovery.nse','smb-protocols.nse','smb-vuln-conficker.nse','smb-vuln-regsvc-dos.nse','smb-vuln-webexec.nse','smb-vuln-webexec']
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV -sU --script='+s+' --script-args="smbusername=admin,smbpass=passowrd,webexec_gui_command=cmd,webexec_command=net user test test /add"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def rpc(host):
    scripts=['realvnc-auth-bypass.nse','rdp-vuln-ms12-020.nse']
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def nfs(host):
    scripts=['nfs-showmount']
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def ftp(host):
    scripts=['ftp-anon.nse','ftp-bounce.nse','ftp-libopie','ftp-proftpd-backdoor.nse','ftp-vsftpd-backdoor.nse']
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV --script='+s+' --script-args="ftp-anon.maxlist=-1"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)

def dns(host):
    scripts=['dns-cache-snoop.nse','dns-check-zone.nse','dns-recursion.nse']
    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress") as bar:
        for s in scripts:
            res=filter_data(_scan(host,'-sV -sU --script='+s+' --script-args="dns-cache-snoop.mode=timed,dns-cache-snoop.domains={nshm.com,sakurity.com,primeinfoserv.com},dns-check-zone.domain=example.com"'))
            if len(json.loads(res))>0:
                data.append((res))
            bar()
    return (data)


def scanner(host):
    scripts=['ssl-enum-ciphers','http-vuln-wnr1000-creds.nse','sslv2-drown.nse','smtp-strangeport.nse','ssl-heartbleed.nse','http-sql-injection.nse','ssl-cert.nse','http-passwd.nse','ms-sql-empty-password.nse','http-rfi-spider.nse','smb-security-mode.nse','smb-vuln-conficker.nse','ssl-cert-intaddr.nse','http-fileupload-exploiter.nse','http-traceroute.nse','tls-ticketbleed.nse','ssh-publickey-acceptance.nse','http-open-redirect.nse','ssl-ccs-injection.nse','http-iis-short-name-brute.nse','http-xssed.nse','sshv1.nse','http-internal-ip-disclosure.nse','http-avaya-ipoffice-users.nse','sslv2.nse','smb-vuln-webexec.nse','http-methods.nse','http-open-proxy.nse','http-shellshock.nse','http-ls.nse','http-vmware-path-vuln.nse','smtp-commands.nse','http-git.nse','mysql-empty-password.nse','http-awstatstotals-exec.nse','http-phpmyadmin-dir-traversal.nse','http-comments-displayer.nse','http-gitweb-projects-enum.nse','http-robots.txt.nse','http-vuln-misfortune-cookie.nse','http-apache-negotiation.nse','http-brute.nse','http-cross-domain-policy.nse','http-iis-webdav-vuln.nse','ssl-date.nse','smb-os-discovery.nse','http-trace.nse','smb2-security-mode.nse','ssl-dh-params.nse','http-put','ms-sql-hasdbaccess.nse','http-huawei-hg5xx-vuln.nse','smtp-open-relay.nse','smb-vuln-webexec','ssl-poodle.nse','http-cors','http-malware-host.nse','smb-vuln-regsvc-dos.nse','http-phpself-xss.nse','http-config-backup.nse','ip-https-discover.nse','http-webdav-scan.nse','ssh-hostkey.nse','http-method-tamper.nse','http-userdir-enum.nse','ssl-known-key.nse','http-dombased-xss.nse','smb2-vuln-uptime.nse','http-csrf.nse','http-frontpage-login.nse','http-google-malware.nse','http-litespeed-sourcecode-download.nse','ssh2-enum-algos.nse','http-slowloris-check.nse','smb-double-pulsar-backdoor.nse ','smb-protocols.nse','ssh-auth-methods.nse','http-cookie-flags','ms-sql-xp-cmdshell.nse','realvnc-auth-bypass.nse','rdp-vuln-ms12-020.nse','nfs-showmount','ftp-anon.nse','ftp-bounce.nse','ftp-libopie','ftp-proftpd-backdoor.nse','ftp-vsftpd-backdoor.nse','dns-cache-snoop.nse','dns-check-zone.nse','dns-recursion.nse']

    data=[]
    with alive_bar(len(scripts),force_tty=True,title="Progress",bar="halloween") as bar:
        for s in scripts:
            if re.search('dns',s,re.IGNORECASE) or re.search('smb',s,re.IGNORECASE):
                res=filter_data(_scan(host,'-sV --script='+s+' --script-args="userdb=users.lst, passdb=pass.lst, ssh-brute.timeout=4s,ssh_hostkey=all, ssh-run.cmd=ls , ssh-run.username=admin, ssh-run.password=password,ssh.usernames={\'root\', \'user\'}, publickeys={\'./id_rsa1.pub\', \'./id_rsa2.pub\'},ssh.privatekeys={\'./id_rsa1\', \'./id_rsa2\'},ssh.user=\'root\',smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1,basepath=/cf/adminapi/, basepath=/cf/, http-aspnet-debug.path=/path,http-awstatstotals-exec.cmd=uname, http-awstatstotals-exec.uri=/awstats/index.php, http-cross-domain-policy.domain-lookup=true, http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\',http-put.url=\'/uploads/rootme.php\', http-put.file=\'/tmp/rootme.php\', uri=/cgi-bin/bin, cmd=ls,mssql.instance-all,mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd=ipconfig,smbusername=admin,smbpass=passowrd,webexec_gui_command=cmd,webexec_command=net user test test /add,ftp-anon.maxlist=-1,dns-cache-snoop.mode=timed,dns-cache-snoop.domains={nshm.com,sakurity.com,primeinfoserv.com},dns-check-zone.domain=example.com"'))
            else:
                res=filter_data(_scan(host,'-sV --script='+s+' --script-args="userdb=users.lst, passdb=pass.lst, ssh-brute.timeout=4s,ssh_hostkey=all, ssh-run.cmd=ls , ssh-run.username=admin, ssh-run.password=password,ssh.usernames={\'root\', \'user\'}, publickeys={\'./id_rsa1.pub\', \'./id_rsa2.pub\'},ssh.privatekeys={\'./id_rsa1\', \'./id_rsa2\'},ssh.user=\'root\',smtp-open-relay.domain=sakurity.com,smtp-open-relay.ip=127.0.0.1,basepath=/cf/adminapi/, basepath=/cf/, http-aspnet-debug.path=/path,http-awstatstotals-exec.cmd=uname, http-awstatstotals-exec.uri=/awstats/index.php, http-cross-domain-policy.domain-lookup=true, http-put.url=\'/dav/nmap.php\',http-put.file=\'/root/Desktop/nmap.php\',http-put.url=\'/uploads/rootme.php\', http-put.file=\'/tmp/rootme.php\', uri=/cgi-bin/bin, cmd=ls,mssql.instance-all,mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd=ipconfig,smbusername=admin,smbpass=passowrd,webexec_gui_command=cmd,webexec_command=net user test test /add,ftp-anon.maxlist=-1,dns-cache-snoop.mode=timed,dns-cache-snoop.domains={nshm.com,sakurity.com,primeinfoserv.com},dns-check-zone.domain=example.com"'))



            if len(json.loads(res))>0:
                data.append((res))
                bar()
    return (data)



host=sys.argv[1]
scanner(host)