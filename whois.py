#!/usr/bin/python

# automates whois grabbin'
# Python 2.7, I suppose
# two main weaknesses:
# (1) relies on a lookup table for whois servers (out of date, whatever)
# (2) domain extensions are referenced by their last three letters
#     ... that's fine for com, .in, etc... but gets a little wonky for
#     .museum --> eum    or  .mobi --> obi
#     could stand to make that more robust
 
# a lookup table of whois servers
def whois_server_lookup(lookup_extension):
    serverlookup = {
		'.ac':'whois.nic.ac',
		'.ae':'whois.aeda.net.ae',
		'ero':'whois.aero',
		'.af':'whois.nic.af',
		'.ag':'whois.nic.ag',
		'.al':'whois.ripe.net',
		'.am':'whois.amnic.net',
		'.as':'whois.nic.as',
		'sia':'whois.nic.asia',
		'.at':'whois.nic.at',
		'.au':'whois.aunic.net',
		'.ax':'whois.ax',
		'.az':'whois.ripe.net',
		'.ba':'whois.ripe.net',
		'.be':'whois.dns.be',
		'.bg':'whois.register.bg',
		'.bi':'whois.nic.bi',
		'biz':'whois.neulevel.biz',
		'.bj':'www.nic.bj',
		'.br':'whois.nic.br',
		'.bt':'whois.netnames.net',
		'.by':'whois.ripe.net',
		'.bz':'whois.belizenic.bz',
		'.ca':'whois.cira.ca',
		'cat':'whois.cat',
		'.cc':'whois.nic.cc',
		'.cd':'whois.nic.cd',
		'.ch':'whois.nic.ch',
		'.ck':'whois.nic.ck',
		'.cl':'nic.cl',
		'.cn':'whois.cnnic.net.cn',
		'.cn.com':'whois.centralnic.com',
		'.co':'whois.nic.co',
		'.nl':'whois.co.nl',
		'com':'whois.internic.com',
		'oop':'whois.nic.coop',
		'.cx':'whois.nic.cx',
		'.cy':'whois.ripe.net',
		'.cz':'whois.nic.cz',
		'.de':'whois.denic.de',
		'.dk':'whois.dk-hostmaster.dk',
		'.dm':'whois.nic.cx',
		'.dz':'whois.nic.dz',
		'edu':'whois.internic.net',
		'.ee':'whois.tld.ee',
		'.eg':'whois.ripe.net',
		'.es':'whois.ripe.net',
		'.eu':'whois.eu',
		'.fi':'whois.ficora.fi',
		'.fo':'whois.nic.fo',
		'.fr':'whois.nic.fr',
		'.gb':'whois.ripe.net',
		'.ge':'whois.ripe.net',
		'.gl':'whois.nic.gl',
		'.gm':'whois.ripe.net',
		'gov':'whois.nic.gov',
		'.gr':'whois.ripe.net',
		'.gs':'whois.nic.gs',
		'.hk':'whois.hknic.net.hk',
		'.hm':'whois.registry.hm',
		'.hn':'whois2.afilias-grs.net',
		'.hr':'whois.ripe.net',
		'.hu':'whois.nic.hu',
		'.ie':'whois.domainregistry.ie',
		'.il':'whois.isoc.org.il',
		'.in':'whois.inregistry.net',
		'nfo':'whois.afilias.info',
		'int':'whois.isi.edu',
		'.io':'whois.nic.io',
		'.iq':'vrx.net',
		'.ir':'whois.nic.ir',
		'.is':'whois.isnic.is',
		'.it':'whois.nic.it',
		'.je':'whois.je',
		'obs':'jobswhois.verisign-grs.com',
		'.jp':'whois.jprs.jp',
		'.ke':'whois.kenic.or.ke',
		'.kg':'whois.domain.kg',
		'.kr':'whois.nic.or.kr',
		'.la':'whois2.afilias-grs.net',
		'.li':'whois.nic.li',
		'.lt':'whois.domreg.lt',
		'.lu':'whois.restena.lu',
		'.lv':'whois.nic.lv',
		'.ly':'whois.lydomains.com',
		'.ma':'whois.iam.net.ma',
		'.mc':'whois.ripe.net',
		'.md':'whois.nic.md',
		'.me':'whois.nic.me',
		'mil':'whois.nic.mil',
		'.mk':'whois.ripe.net',
		'obi':'whois.dotmobiregistry.net',
		'.ms':'whois.nic.ms',
		'.mt':'whois.ripe.net',
		'.mu':'whois.nic.mu',
		'.mx':'whois.nic.mx',
		'.my':'whois.mynic.net.my',
		'ame':'whois.nic.name',
		'net':'whois.internic.net',
		'.nf':'whois.nic.cx',
		'.ng':'whois.nic.net.ng',
		'.nl':'whois.domain-registry.nl',
		'.no':'whois.norid.no',
		'.nu':'whois.nic.nu',
		'.nz':'whois.srs.net.nz',
		'org':'whois.pir.org',
		'.pl':'whois.dns.pl',
		'.pr':'whois.nic.pr',
		'pro':'whois.registrypro.pro',
		'.pt':'whois.dns.pt',
		'.pw':'whois.nic.pw',
		'.ro':'whois.rotld.ro',
		'.ru':'whois.tcinet.ru',
		'.sa':'saudinic.net.sa',
		'.sb':'whois.nic.net.sb',
		'.sc':'whois2.afilias-grs.net',
		'.se':'whois.nic-se.se',
		'.sg':'whois.nic.net.sg',
		'.sh':'whois.nic.sh',
		'.si':'whois.arnes.si',
		'.sk':'whois.sk-nic.sk',
		'.sm':'whois.nic.sm',
		'.st':'whois.nic.st',
		'.so':'whois.nic.so',
		'.su':'whois.tcinet.ru',
		'.tc':'whois.adamsnames.tc',
		'tel':'whois.nic.tel',
		'.tf':'whois.nic.tf',
		'.th':'whois.thnic.net',
		'.tj':'whois.nic.tj',
		'.tk':'whois.nic.tk',
		'.tl':'whois.domains.tl',
		'.tm':'whois.nic.tm',
		'.tn':'whois.ripe.net',
		'.to':'whois.tonic.to',
		'.tp':'whois.domains.tl',
		'.tr':'whois.nic.tr',
		'vel':'whois.nic.travel',
		'.tw':'whois.twnic.net.tw',
		'.tv':'whois.nic.tv',
		'.tz':'whois.tznic.or.tz',
		'.ua':'whois.ua',
		'.uk':'whois.nic.uk',
		'.us':'whois.nic.us',
		'.uy':'nic.uy',
		'.uy.com':'whois.centralnic.com',
		'.uz':'whois.cctld.uz',
		'.va':'whois.ripe.net',
		'.vc':'whois2.afilias-grs.net',
		'.ve':'whois.nic.ve',
		'.vg':'whois.adamsnames.tc',
		'.ws':'whois.website.ws',
		'xxx':'whois.nic.xxx',
		'.yu':'whois.ripe.net'}
    return serverlookup[lookup_extension]

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
		
    #get the extension , .com , .org , .edu, or last three letters
	# could stand to make this a bit more sophisticated
    ext = domain[-3:]
     
    # check lookup table for proper whois server 
    specific_whois_server = whois_server_lookup(ext)
	
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