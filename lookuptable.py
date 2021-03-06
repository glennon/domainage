# a lookup table of whois servers
# should investigate whether subdomains such as .co.uk have a different whois_server than .uk
# my first impression is yes... so next, it's a matter of figuring out which ones are important.
# then the main whois code needs to change its domain parsing method to handle the case.

# .com is wonkier than I first thought too. different servers have them... 
# need to find the central server to query, acquire the sub whois server, and then query that.

def whois_server_lookup(lookup_extension):
    serverlookup = {
		'ac':'whois.nic.ac',
		'ae':'whois.aeda.net.ae',
		'aero':'whois.aero',
		'af':'whois.nic.af',
		'ag':'whois.nic.ag',
		'al':'whois.ripe.net',
		'am':'whois.amnic.net',
		'as':'whois.nic.as',
		'asia':'whois.nic.asia',
		'at':'whois.nic.at',
		'au':'whois.aunic.net',
		'ax':'whois.ax',
		'az':'whois.ripe.net',
		'ba':'whois.ripe.net',
		'be':'whois.dns.be',
		'bg':'whois.register.bg',
		'bi':'whois.nic.bi',
		'biz':'whois.neulevel.biz',
		'bj':'www.nic.bj',
		'br':'whois.nic.br',
		'bt':'whois.netnames.net',
		'by':'whois.ripe.net',
		'bz':'whois.belizenic.bz',
		'ca':'whois.cira.ca',
		'cat':'whois.cat',
		'cc':'whois.nic.cc',
		'cd':'whois.nic.cd',
		'ch':'whois.nic.ch',
		'ck':'whois.nic.ck',
		'cl':'nic.cl',
		'cn':'whois.cnnic.net.cn',
		'.cn.com':'whois.centralnic.com',
		'co':'whois.nic.co',
		'nl':'whois.co.nl',
		'com':'whois.internic.com',
		'coop':'whois.nic.coop',
		'cx':'whois.nic.cx',
		'cy':'whois.ripe.net',
		'cz':'whois.nic.cz',
		'de':'whois.denic.de',
		'dk':'whois.dk-hostmaster.dk',
		'dm':'whois.nic.cx',
		'dz':'whois.nic.dz',
		'edu':'whois.internic.net',
		'ee':'whois.tld.ee',
		'eg':'whois.ripe.net',
		'es':'whois.ripe.net',
		'eu':'whois.eu',
		'fi':'whois.ficora.fi',
		'fo':'whois.nic.fo',
		'fr':'whois.nic.fr',
		'gb':'whois.ripe.net',
		'ge':'whois.ripe.net',
		'gl':'whois.nic.gl',
		'gm':'whois.ripe.net',
		'gov':'whois.nic.gov',
		'gr':'whois.ripe.net',
		'gs':'whois.nic.gs',
		'hk':'whois.hknic.net.hk',
		'hm':'whois.registry.hm',
		'hn':'whois2.afilias-grs.net',
		'hr':'whois.ripe.net',
		'hu':'whois.nic.hu',
		'ie':'whois.domainregistry.ie',
		'il':'whois.isoc.org.il',
		'in':'whois.inregistry.net',
		'info':'whois.afilias.info',
		'int':'whois.isi.edu',
		'io':'whois.nic.io',
		'iq':'vrx.net',
		'ir':'whois.nic.ir',
		'is':'whois.isnic.is',
		'it':'whois.nic.it',
		'je':'whois.je',
		'jobs':'jobswhois.verisign-grs.com',
		'jp':'whois.jprs.jp',
		'ke':'whois.kenic.or.ke',
		'kg':'whois.domain.kg',
		'kr':'whois.nic.or.kr',
		'la':'whois2.afilias-grs.net',
		'li':'whois.nic.li',
		'lt':'whois.domreg.lt',
		'lu':'whois.restena.lu',
		'lv':'whois.nic.lv',
		'ly':'whois.lydomains.com',
		'ma':'whois.iam.net.ma',
		'mc':'whois.ripe.net',
		'md':'whois.nic.md',
		'me':'whois.nic.me',
		'mil':'whois.nic.mil',
		'mk':'whois.ripe.net',
		'mobi':'whois.dotmobiregistry.net',
		'ms':'whois.nic.ms',
		'mt':'whois.ripe.net',
		'mu':'whois.nic.mu',
		'museum':'whois.museum',
		'mx':'whois.nic.mx',
		'my':'whois.mynic.net.my',
		'name':'whois.nic.name',
		'net':'whois.internic.net',
		'nf':'whois.nic.cx',
		'ng':'whois.nic.net.ng',
		'nl':'whois.domain-registry.nl',
		'no':'whois.norid.no',
		'nu':'whois.nic.nu',
		'nz':'whois.srs.net.nz',
		'org':'whois.pir.org',
		'pl':'whois.dns.pl',
		'pr':'whois.nic.pr',
		'pro':'whois.registrypro.pro',
		'pt':'whois.dns.pt',
		'pw':'whois.nic.pw',
		'ro':'whois.rotld.ro',
		'ru':'whois.tcinet.ru',
		'sa':'saudinic.net.sa',
		'sb':'whois.nic.net.sb',
		'sc':'whois2.afilias-grs.net',
		'se':'whois.nic-se.se',
		'sg':'whois.nic.net.sg',
		'sh':'whois.nic.sh',
		'si':'whois.arnes.si',
		'sk':'whois.sk-nic.sk',
		'sm':'whois.nic.sm',
		'st':'whois.nic.st',
		'so':'whois.nic.so',
		'su':'whois.tcinet.ru',
		'tc':'whois.adamsnames.tc',
		'tel':'whois.nic.tel',
		'tf':'whois.nic.tf',
		'th':'whois.thnic.net',
		'tj':'whois.nic.tj',
		'tk':'whois.nic.tk',
		'tl':'whois.domains.tl',
		'tm':'whois.nic.tm',
		'tn':'whois.ripe.net',
		'to':'whois.tonic.to',
		'tp':'whois.domains.tl',
		'tr':'whois.nic.tr',
		'travel':'whois.nic.travel',
		'tw':'whois.twnic.net.tw',
		'tv':'whois.nic.tv',
		'tz':'whois.tznic.or.tz',
		'ua':'whois.ua',
		'uk':'whois.nic.uk',
		'us':'whois.nic.us',
		'uy':'nic.uy',
		'uy.com':'whois.centralnic.com',
		'uz':'whois.cctld.uz',
		'va':'whois.ripe.net',
		'vc':'whois2.afilias-grs.net',
		've':'whois.nic.ve',
		'vg':'whois.adamsnames.tc',
		'ws':'whois.website.ws',
		'xxx':'whois.nic.xxx',
		'yu':'whois.ripe.net'}
    return serverlookup[lookup_extension]
