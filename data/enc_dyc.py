import bane,sys,os

data=sys.argv[1]

def enc(data):
    temp=[]
    for i in data:
        temp.append(str(ord(i)+len(data))+chr(ord(i)+len(data)))

    res=bane.xor_string( data, str("".join(map(str,temp))) )
    return res,str("".join(map(str,temp)))






res,key=enc(data)
print(res)