#!/usr/bin/python

# automates whois grabbin'
# Python 2.7, I suppose
# main weaknesses:
# (1) relies on a lookup table for whois servers (out of date, whatever)
# (2) cannot handle compound domains such as .co.uk
 
import lookuptable

def perform_whois(server,query) :
    #socket connect
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((server , 43))
    #send data
    s.send(query + '\r\n')
    # receive reply in pieces
    returnmessage = ''
    while len(returnmessage) < 10000:
        piece = s.recv(128)
        if(piece == ''):
            break
        returnmessage = returnmessage + piece
     
    return returnmessage
	
def get_the_whois(domain):
     
    #remove http and www
    domain = domain.replace('http://','')
    if(domain.startswith('www.')):
        domain = domain[4:]
		
    #get the extension , .com , .org , .edu
    domainlength = len(domain)
    notadot = True
    counteralpha = domainlength - 1
    while (notadot):
        dotchecker = domain[counteralpha]
        if dotchecker == ".":
            # print("dot found at position: " + str(counteralpha))
            counteralpha = counteralpha + 1
            # print("The suffix is: " + domain[int(counteralpha):])
            ext = domain[int(counteralpha):]
            notadot = False
        else:
            counteralpha = counteralpha - 1
	
	
	 
    # check lookup table for proper whois server 
    specific_whois_server = lookuptable.whois_server_lookup(ext)
	
	# perform the actual whois
    whois_msg = perform_whois(specific_whois_server,domain)
	
	# return 
    return whois_msg
# end
	
	
# ...the main program...
import socket, sys
# input the domain name
domain_name = sys.argv[1]
# output the whois
print get_the_whois(domain_name)
