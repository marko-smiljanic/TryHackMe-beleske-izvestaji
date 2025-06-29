# TShark beleske i vezbanje 

tshark je CLI alat i sluzi za detaljnu analizu pakete i automatizaciju pomocu skripti  

predstavlja CLI verziju wiresharka

**otici na lokaciju kroz cmd i kucati komandu capinfos za fajl. Odgovoriti koja je ripemd160 vrednost**

`capinfos demo.pcapng`

tshark osnovne komande: 

`tshark -h` help page  
`tshark -v` version info  
`tshark -D` list sniffing interfejsa  
```
tshark -i 1       -odabir interfejsa za snimanje saobracaja uzivo 
tshark -i ens55   
``` 
`tshark` sniffing saobracaja kao tcp dump   

sniffing je jedna od osnovne funkcionalnosti tshark-a. odredjeni interfejsi za sniffing mogu biti povezani sa odredjenim zadacima. zbog toga je jako bitno odabrati dobar interfejs   

ako ne odaberemo ni jedan interfejs, podrazumevano se koristi prvi  

ako navedemo `tshark -i 1` to znaci da nije odabran ni jedan interfejs  

**koja je dostupna verzija tsharka na vm**

izvrsimo komandu sa sudo za proveru verzije (-v)

**koliko ima ukupno interfejsa dostupnih za tshark sniffing na vm**

sa sudo izvrsimo komandu za pregled interfejsa (v)

tshark komande:  

- `tshark -r demo.pcapng` citanje fajla   
- `tshark -c 10` zaustavi snimanje saobracaja nakon 10 paketa  
- `tshark -w file.pcap` zapisi snimnjeni saobracaj u fajl   
- `tshark -V` detaljne informacije za svaki paket (ova opcija je slicna detaljima iz wireshark-a)  
- `tshark -q` silent mode - obustavljanje slanja paketa na terminalu  
- `tshark -x` prikaz bajtova paketa u hex i ascii 


**procitati pcapng fajl, pristupiti 29tom paketu i procitati tcp flags**

izvrsim komandu (mroam biti na lokaciji gde se nalazi fajl za citanje + sudo) i onda nadjem pod rednim brojem (frame 29) i procitam sta mi treba.  

Citam sa detlajima paketa (-V) i procitam prvih 29 (-c), i odmah dobijem ovog trazenog jer je poslednji iscitan.  

`tshark -r demo.pcapng -V -c 29`

## Napomena: 

> Malo mi je glupo sto trosim vreme da opisem ovakve trivijalne stvari **ali moram tako jer zelim da imam potpunu dokumentaciju o mom radu**  
> dosta zadataka se cini sada trivijalnim jer sam prosao zeek i snort pre ovoga i tamo sam skontao kako rade ovakvi alati i kako se koriste  

**koja je ack vrednost 25og paketa**

ista stvar kao prethodni zadatak, primenim filter, ucitam prvih 25 paketa i nadjem sta treba 

`tshark -r demo.pcapng -V -c 25`

**koja je velicina prozora 9og paketa**

isto kao prosli zadatak, primenim filter i procitam trazeni paket trazeci ono sto se zahteva  

> posto -V daje velike kolicine teksta u cmd-u, ja prekopiram sve vezano za trazeni paket i onda nalepim u nekom editoru i pomocu CTRL + F pretrazim fajl po kljucnoj reci da bih brze nasao ono sto mi treba  

`tshark -r demo.pcapng -V -c 9`

tshark se moze konfigurisati da broji/snima pakete i da se zaustavlja na odredjenoj tacki  

tshark komande u rezimu sniffing:  

`-a` zaustavljanje snimanja nakon odredjenog ciklusa:   

- `tshark -w test.pcap -a duration:1` prati saobracaj i zaustavi se nakon x sekundi i zapisi izlaz u fajl  
- `tshark -w test.pcap -a filesize:10` zausustavlja snimanje nakon dostizanja velicine datoteke (jedinica je KB)  
- `tshark -w test.pcap -a filesize:10 -a files:3` zaustavlja snimanje nakon postignute velicine i postavljanje maksimalnog broja izlaznih datoteka   

`-b` sve isto samo sto sa ovim definisemo uslove snimanja za visestruke cikluse/petlje:  
- `tshark -w test.pcap -b duration:1` 
- `tshark -w test.pcap -a filesize:10` 
- `tshark -w test.pcap -a filesize:10 -a files:3`

mozemo i kombinovati `-b` i `-a` parametre. treba biti oprezan pri koriscenu parametra beskonacne petlje, moramo imati neki nacin da ga zaustavimo 

`tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5` kombinovanje moze i sa istim parametrima, u ovom slucaju sa `-a`  

u tshark-u imamo opcije filtriranja uzivo tokom snimanja i filtriranje nakon snimanja (filteri za prikaz)   

tshark podrzava wireshark filtere i Berekli filtere   

filteri za snimanje uzivo se podesavaju pre pocetka snimanja i ne mogu se menjati kada se zapocne snimanje  

`-f` filteri za snimanje  
`-Y` filteri za prikaz 

tshark **CAPTURE** filteri: 

- `tshark -f "host 10.10.10.10"` filtriranje hosta  
- `tshark -f "net 10.10.10.0/24"` filtriranje mreznog opsega  
- `tshark -f "port 80"` filtriranje porta   
- `tshark -f "portrange 80-100"` filtriranje opsega portova  
- `tshark -f "src host 10.10.10.10"` filtriranje izvorne adrese
- `tshark -f "dst host 10.10.10.10"` filtriranje odredisne adrese 
- `tshark -f "tcp"` filtrira protokl 
- `tshark -f "ether host F8:DB:C5:A2:5D:81"` filtriranje mac adrese 
- `tshark -f "ip proto 1"` filtriranje ip protokola 1 (broj jedan je za icmp protokol - lista svih dodeljenih brojeva protokolima: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)   

**primer za simulaciju dogadjaja + filtriranje:**  

ovo se radi u terminator terminalima  

filtriranje hosta: 

`curl tryhackme.com` u jednom terminalu generisemo saobracaj http upit na navedenu adresu
`tshark -f "host tryhackme.com"` u drugom terminalu hvatamo taj host  

filtriranje ip adresa:  

`nc 10.10.10.10 4444 -vw 5` generisanje saobracaja pomocu netcat-a, vreme cekanja podeseno na 5 sec  
`tshark -f "host 10.10.10.10"` filter za snimanje za odredjenu ip adresu  

filtriranje portova:   

`nc 10.10.10.10 4444 -vw 5` 
`tshark -f "port 4444"`

filtriranje protokla:  

`nc -u 10.10.10.10 4444 -vw 5` za udp
`tshark -f "udp"`

**sledeci zadaci se pokrecu u terminator terminalima**

terminator terminal omogucava da imam vise podeljenih terminala u istom prozoru, olaksava rad na vise zadataka istovremeno, komanda za pokretanje je `terminator`    

**koji je broj paketa sa SYN bajtovima**

syn flag je za pocetak tcp konekcije, wc -l broji koliko ima takvih paketa    

prvo kucamo komandu za terminator:  

`terminator`

u gornjem terminalu pokrecemo komandu `tshark -f "host 10.10.10.10" -w testfajl.pcap`   

u donjem terminalu pokrecemo komandu `curl -v 10.10.10.10` ovu komandu pokrecemo dok se radi snimanje u gornjem  

> Napomena: ove ip adrese stoje u primeru zadatka  

sacekamo par sekundi i u gornjem terminalu zatvorimo snimanje (CTRL + c)   

onda u primarnom terminalu (kada smo zatvorili terminatore) uradimo komandu da nas novokreirani .pcap fajl procitamo i izvucemo sta treba  

`sudo tshark -r testfajl.pcap | grep "SYN"`

druga komanda kojom gadjamo tcp.flags sa tshark filterom -Y:   

`sudo tshark -r testfajl.pcap -Y "tcp.flags.syn == 1" | wc -l`

**koji je broj pakete poslat na adresu: 10.10.10.10**

koristimo isti onaj nas test fajl koji smo napravili u proslom zadatku uz pomoc simulacije skeniranja sa terminatorima  

primenimo filter nad fajlom i onda izbrojimo koliko se puta destination ip adresa pojavljuje ova trazena. Mejutim resenje nije bas dobro jer moram da brojim i przim oci nad gomilom podataka    

`sudo tshark -r testfajl.pcap`

opet forsiram primenu -Y tshark filtera da bih dobio gotovo resenje bes citanja celog pcap fajla  

`sudo tshark -r testfajl.pcap -Y "ip.dst == 10.10.10.10" | wc -l`

**koliki je broj paketa koji ima ACK bajtove**

primenim filter i procitam broj  

`sudo tshark -r testfajl.pcap -Y "tcp.flags.syn == 1" | wc -l`

**OVAJ FITLER NE RADI, ODNOSNO ONAJ BROJ KOJI MI ON POKAZUJE NIJE RESENJE**

zbog cega se to desilo ne znam, mozda moje snimanje saobracaja nije uradjeno isto kao sto su oni zamislili  

zbog toga se cupam sa ovim drugim filterima i prebrojavam pojave ack-a:  

`sudo tshark -r testfajl.pcap | grep "ACK"` 
`sudo tshark -r testfajl.pcap -Y "tcp.flags.ack == 1"`

kada primenim jedan od ova dva filtera vidim da ima viska rezultata odnosno izbrojani su ACK-ovi i sa nekih drugih mesta  

mesto gde bi trebali da se gledaju ACK vrednosti su unutar zagrada [xxx, ACK]. ACK-ovi se pojavljuju i na drugim mestima koja daju visak rezultata. Treba pazljivo gledati gde je pronadjen ACK  


tshark **DISPLAY** filteri (filteri za pcap fajlove, ne za uzivo snimanje): 

u filtere se mora ubaciti i citanje fajla sa -r  

- `tshark -Y 'ip.addr == 10.10.10.10'` filtrira ip adresu bez specificiranog smera   
- `tshark -Y 'ip.addr == 10.10.10.0/24'` filtrira ceo opseg   
- `tshark -Y 'ip.src == 10.10.10.10'` filtrira izvornu adresu    
- `tshark -Y 'ip.dst == 10.10.10.10'` ili odredisnu    
- `tshark -Y 'tcp.port == 80'` tcp port   
- `tshark -Y 'tcp.srcport == 80'` tcp izvorni port   
- `tshark -Y 'http'` sve http pakete   
- `tshark -Y "http.response.code == 200"` trazi 200 ok odgovor servera  
- `tshark -Y 'dns'` sve dns pakete  
- `tshark -Y 'dns.qry.type == 1'` sve dns A pakete  

## ova soba je trebala da se nalazi pre onog prethodnog zadatka jer su se tamo koristili ovakvi filteri a tek posle su objasnjeni  

**koristi se demo.pcapng fajl za sledece zadatke**

**koji je broj paketa sa 65.208.228.223 ip adresom**

primenim filter i iscitam broj  

`tshark -r demo.pcapng -Y 'ip.addr == 65.208.228.223' | wc -l`

**koji je broj paketa sa tcp portom 3371**

`tshark -r demo.pcapng -Y 'tcp.port == 3371' | wc -l`

**koji je broj paketa sa adresom 145.254.160.237 kao izvornom**

`tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237' | wc -l`

**pokrenuti prethodni upit i videti koji je output (novi upit nastaviti na prethodni). koji je broj dupliranih paketa**

resenje ovoga sam nasao tako sto sam prvo otvorio ceo fajl da vidim sta bi mogao biti ispis za duplicate  

`tshark -r demo.pcapng` 

nakon ovoga sam video da je ispis koji odgovara [TCP, Dup, ACK, xxx]. znaci da treba da trazim Dup rec. Verovatno postoji tshark filter koji ovo nalazi ali ja ne mogu da ubodem koji je, jer mi ni jedan ne radi    

`tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237' | grep "Dup"` 

filter sa `tcp.analysis.duplicate` meni ne radi !!

# Statistika  

`tshark --color` daje obojeni izlaz, slicno kao u wiresharku  
`tshark -z help` statistika 
`tshark -z filter` upotreba filtera 
`-q` paremtar omogucava veci fokus na statistiku, tj. da se ne prikazuju i paketi  

`-z io,phs -q` parametri koji omogucavaju hijerarhiju protokola   
`tshark -r demo.pcapng -z io,phs,udp -q` primena filtera sa hijerarhijom protokola, ali se fokusiramo na udp   
`-z plen,tree -q` statistika za prikaz duzine paketa   
`-z endpoints,ip -q` statistika za endopointe (`eth, ip, ipv6, tcp, udp, wlan`)   
`-z conv,ip -q` statistika za konverzaciju pregleda saobracaja izmedju dva endpointa  
`-z expert -q` statistika za experts info (podsetnik: experts info smo koristili u wiresharku za pregled nekakvih alerta)  

**koja je vrednost bajtova za tcp protokol**

primenimo osnovni filter i pronadjemo vrednost za tcp protokol. Ovaj filter samo prikaze hijerarhiju u vidu stabla i informacije o frame i bajtovima  

`tshark -r write-demo.pcap -z io,phs -q`

**u kom redu duzine paketa je prikazan nas paket?**

primenim filter i pogledam koji su opsezi duzine paketa i gde tacno upada nas paket od 62 bajta. Samo izvadim vrednost iz tabele za opseg velicina  

`tshark -r write-demo.pcap -z plen,tree -q`

**sta je summary od expert info-a**

primenim filter i procitam summary tekst  

`tshark -r write-demo.pcap -z expert -q`

**koja ip adresa postoji u svim ipv4 konverzacijama, uneti u defang formatu** 

primenim filter, pronadjem adresu i napisem defang format kao odgovor  

`tshark -r write-demo.pcap -z conv,ip -q`

# Statistika II  

filtriranje hosta po ip i ipv6 protokolu:   

- `-z ip_hosts,tree -q`
- `-z ipv6_hosts,tree -q`

sa ovim filterima mozemo da se fokusiramo na izvorisnu i odredisnu adresu:   

- `-z ip_srcdst,tree -q`
- `-z ipv6_srcdst,tree -q`

ovi filteri su za ip i ipv6 sa fokusom na servise i portove  

- `-z dests,tree -q`  
- `-z ipv6_dests,tree -q`

- `-z dns,tree -q` statistika o dns paketima  

statistika za http:

- `-z http,tree -q` brojac paketa i statusa za http  
- `-z http2,tree -q` brojac paketa i statusa za https (http2)  
- `-z http_srv,tree -q` raspored opterecenja  
- `-z http_req,tree -q` zahtevi  
- `-z http_seq,tree -q` odgovori   

**koja ip adresa se pojavljuje 7 puta? upisati adresu u defang formatu**

izvrsim komandu i odmah dobijem prikaz u tabeli za adrese   

`tshark -r demo.pcapng -z ip_hosts,tree -q`

**koji je procenat destination adrese od adrese iz proslog zadataka**

ukucamo bilo koju od ove dve komande i vidimo procente. Sa prvom cemo dobiti prikaz i source adresa pa treba obratiti paznju na to  

ovde sam imao opasan problem jer 20 minuta nisam mogao da ukucam pravo resenje jer na kraju resenja koje je 6.98 nisam stavio znak %. Na sve treba obracati paznju, bespotrebno    

`tshark -r demo.pcapng -z ip_srcdst,tree -q`
`tshark -r demo.pcapng -z dests,tree -q`

**koja adresa sadrzi 2.33% u destination adresi? upisati defang format adrese**

primenimo iste komande iz prethodnog zadatak samo citamo deruge vrednosti  

**koji je prosek qname len vrednosti: hint traziti u dns statistici**

primenimo komandu i iz tabelarnog prikaza izvuci vrednost iz kolone average - red qname len  

`tshark -r demo.pcapng -z dns,tree -q`

# Statistika III - strimovi, objekti i kredencijali  

ima previse filtera namenjenih za razne svrhe. 

> **NAPOMENA**: vecina ovih komandi su CLI verzije wireshark funkcija  

follow stream komande (prate tokove saobracaja slicno kao wireshark):  

```
TCP Streams: -z follow,tcp,ascii,0 -q
UDP Streams: -z follow,udp,ascii,0 -q
HTTP Streams: -z follow,http,ascii,0 -q
```

- ovo je primer komandi. `-z follow` je glavni parametar,    
- protokoli mogu biti (`http, tcp udp, http2`),  
- prikaz kao `ascii, hex`, broj strima `0, 1, 2, ...`,    
- dodatni parametar `-q`


export object:  

`--export-objects http,/home/ubuntu/Desktop/extracted-by-tshark -q`

- `--export-objects` glavni parametar  
- `dicom, http, imf, smb, tftp` protokoli  
- putanja foldera gde se cuvaju fajlovi  
- `-q` dodatni param  

kredencijali:  

`-z credentials -q`

**koristiti pilozeni fajl i pratiti udp stream 0. koja je vrednost node 0, rezultat zapisati u defang formatu**

izvrsimo komandu i procitamo vrednosti za node 0 i uradimo defang (u defang za ovo idu samo . u [], : se ne stavlja u zagrade)  

`tshark -r demo.pcapng -z follow,udp,ascii,0 -q`

**pratiti http stream 1, koja je referer vredmpst, zapisati kao defang**

izvrsimo komandu i posto je url u pitanju u odgovoru koristim cyber chef za defang jer ne znam kako se rucno radi defang url-a  

`tshark -r demo.pcapng -z follow,http,ascii,1 -q`

**koristiti prilozeni fajl i videti koji je ukupni broj detektovanih kredencijala**

izvrsim komandu i dobijem izlistane sve kredencijale, ali ne mogu da ih izbrojim sa `| wc -l` broj dobijen sa ovim nije tacan odgovor...   

zbog toga sam kopirao ceo output sa kredencijalima u tekst editor koji broji redove (u mom slucaju notepad++) i video koliko ih ima  

ovo je resenje koje je siledzijsko jer sam video tek posle hint za zadatak da se doda `| nl` i da se numerisu redovi u prikazu   

kada sam ovo izvrsio video sam da su prva 3 reda neka nebitna koja nisu kredencijali a `| wc -l` ih je brojao i zbog toga nije tacan rezultat bio  

`tshark -r credentials.pcap -z credentials -q | nl`

kada izvrsimo komandu vidimo detalje vezane za kredencijale kao sto su username i iz kojeg su paketa izvuceni i korisceni protokol (uglavnom FTP)  

# Napredne opcije filtriranja  

slicno kao i u wiresharku   

> napomena: contains i matches se ne mogu koristiti sa poljima koja se sastoje od integer vrednosti, koriscenje hex i regex vrednosti umesto ascii imaju bolju sansu poklapanja  

`contains` case sensitive, pretrazuje vrednosti unutar paketa, slicno kao wireshark find  

- primer: prikazi sve apache servere  
- pisanje filtera: izlistaj sve http pakete gde server fild sadrzi apache keyword  
- primer primene jednog filtera: `http.server contains "Apache"`

`matches` case insensitive, podrzava regex, pretrazuje sablone unutar paketa, kompleksni upiti mogu sadrzati gresku  

- primer: prikazi sve .php i .html stranice
- pisanje: izlistaj sve http pakete gde se kao request method field podudara sa get ili post  
- primer primene jednog filtera: `http.request.method matches "(GET|POST)"`

extract fields: 

`-T fields -e ip.src -e ip.dst -E header=y` 

- `-T fields` kljucna rec  
- `-e <field name>` koji field gadjamo  
- `-E header=y` prikazi field name   

primer primene filtera: `tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5` moze i sa vise izdvojenih fieldova  

mozemo kombinovati razlicite filtere:   

`tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y`

`tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'`

`tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e ip.src -e ip.dst -e http.request.method -E header=y`

**koristiti prilozeni fajl. koji je broj http paketa koji sadrzi keyword "CAFE"**

primenim ovaj filter i vidim sve informacije o paketu koje mi je prikazao  

`tshark -r demo.pcapng -Y 'http contains "CAFE"'`

**filtriraj sve get i post requestove i izvuci packet frame time, koja je prva time vrednost pronadjena**

hint je da se koristi matches i da ovo moze pomoci `-T fields -e frame.time`, ovo je ok sto su dali jer bih inace morao traziti kako se zove field za frame time  

izvrsim ovu komandu i procitam prvu prikazanu vrednost. Obratiti paznju za pisanje ne mogu ova dva spajati sa and jer nije isti tip filtera    

`tshark -r demo.pcapng -T fields -e frame.time -Y 'http.request.method matches "(GET|POST)"'`

# Use cases  

slucajevi koriscenja **koji su najcesce upotrebljavani** kako bi pronasao lako dostupne reultate nakon pregleda statistike i kreiranja plana istrage  

1. **izdvanjanje hostnames-a:**  

izdvanjanje hostname-a iz dhcp paketa. 

`tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname`

izlaz iz ovoga je tesko upravljati kada postoji vise duplih vrednosti, zbog toga je nekad potrebno dodati druge linux komande za upravaljanje i organizovanje cmd-a  
 | 
primer: `| awk NF | sort -r | uniq -c | sort -r`  

awk uklanja prazne redove,  
sort -r sortira rekurzivno pre obrade vrednosti,  
uniq -c prikazati uniq vrednosti i broj pojavljivanja,  
i na kraju konacni sort za sve  

2. **Izdvanjanje DNS upita** 

`tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r`

izdvajanje user agent-a:  `tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r`  

**koristiti odgovarajuci fajl, videti koliko ukupno ima jedinstvenih hostna-eova (koliko razlicitih)**

izvrsim uput i vidim broj, da bih dobio broj izbrojanih svih redova izvucenih iz prethodne komande, mogu rucno da izbrojim u terminalu ili da dodam `wc -l`  

`tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r | wc -l`

**koje je ukupno pojavljivanje prus-pc hostname-a**

ista komanda kao malo pre samo sklonim `wc -l` da bih video koliko se koji hostname pojavljuje  

`tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r`

ili mogu samo `tshark -r hostnames.pcapng -T fields -e dhcp.option.hostname| grep -c "prus-pc"`

**uzeti odg fajl, koji je ukupan broj query-ja najcesceg dns upita**

izvrsim komandu i pogledam prvog jer je sortirano rekurzivno  

`tshark -r dns-queries.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r`

**koristiti odgovarajuci fajl, koji je ukupni broj detektovanih Wfuzz user agents-a**

izvrsim komandu i pogledam i saberem sve pojave wfuzz ua  

`tshark -r user-agents.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r`

moze i ovako da odmah dobijem odgovor: `tshark -r user-agents.pcap -Y 'http.user_agent contains "Wfuzz"' | wc -l`

ali ja ovako ne bih pretrazivao jer moze biti case sensitive i da mi ga ne ispise ako je nazvan drugacije  

**koji je http hostname za nmap scans, odgovor u defang formatu**

posto ne kaze za koji fajl pretpostavicemo da je isti kao za prethodni zadatak  

hint: Enhance the query by adding the "HTTP hostname" information with the "http.host" option.

izvrsim komandu i vidim koji se najcesce pojavljuje  

`tshark -r user-agents.pcap -Y "http.host" -T fields -e http.host` filtriram samo http host header-e i izdvajam samo hostname  

# TShark zadatak - Teamwork  

> **NAPOMENA**: datoteke sa vezbi sadrze stvarne primere, ne treba imati interakciju sa njima van virt. masine. Datoteke, domeni, ip adrese mogu naskoditi nasoj masini  

Tim za pronalazak pretnji je otkrio sumnjivi domen koji moze naskoditi organizaciji.  

Slucaj je dodeljen nama, treba da istrazimo teamwork.pcap u excercise-files  

Alati za koriscenje: TShark i virus total  

**istraziti kontaktirane domene, istraziti te domene sa virus total, koji od njih je oznacen kao maliciozni, napisati u defang formatu**

prvo sto mi je palo na pamet da uradim da pretrazim sve dns pakete  

`tshark -r teamwork.pcap -Y 'dns.qry.type == 1'`

i tu ne vidimo puno razlicitih domena, i odmah mi jedan upada u oci: www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com   

kada ga istrazim na virus total vidim da ima alerta da se koristio za phising  

moglo je i ovako da se uradi: `tshark -r teamwork.pcap -T fields -e http.host | sort -r | uniq`

**koja je url adresa sumnjivog domena prvi put poslata virust total-u**

za ovo moram da pretrazujem u virus total domen otkriven u prethodnom zadatku i da vidim u istoriji  

nasao sam datum ali u zadatku moram da upisem u specificnom formatu sa satima minutima i sekundama, a to nema na virus total pa sam morao da guglam da se snalazim   

**koju poznatu uslugu je domen pokusao da oponasa**

to vidimo iz url-a odmah: paypal  

**koja je ip adresa malicioznog domena, defang**

tu je prednost one komande koju sam primenio u terminalu (da prikazem sve dns A zapise: [URL] A [ip addr]), i tu na kraju vidim koja je adresa  

**koja je email adresa koja je koriscenka, i defang formatu - (format: aaa[at]bbb[.]ccc)**

`tshark -r teamwork.pcap -Y 'frame contains "@"' -x` - ovo moje je malo siledzijsko resenje gde gledam sadrzaj paketa u ascii formatu i trazim adresu, ali je previse ima informacija, a ako dodam -V tek onda ima gomila teksta     

posto nisam siguran koji je protokol koriscen za mej (smtp i imf mi ne daju rezultate), trazim kroz sirove bajtove paketa pattern za mejl adresu  

Kada ne znam kako da izvedem pretragu uvek imam sirove bajtove. Na netu pronadjem regex i grepujem ga na prikaz `-V` koji daje detalje paketa u citljivom formatu    

`tshark -r teamwork.pcap -V | grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'`  

kada ovo izvrsim vidim adresu. `-E` koriscenje regex-a, `-o` da izbaci samo stvari koje su se poklopile a ne cele linije    

ako sklonimo `-o` onda nam izbaci cele linije i tu vidimo da se ovo moglo pronaci pod grep "user", znaci : `tshark -r teamwork.pcap -V | grep "user"`, jer je ovaj mejl izgleda iz neke forme  

a moze se pronaci i ovako: `tshark -r teamwork.pcap -V | grep "@"`, tada isto dobijemo gomilu podataka ali lakse proletimo kroz njih, jer nam izdvoji sva poklapanja  

imam osecaj da se ovo moglo dosta lakse uraditi ali ne znam kako bi moglo, jednostavno preko protokola ne mogu da dodjem do mejl adrese  

pokusao sam i sa extract object ali dobijem brdo nekih stvari za koje opet treba rucna pretraga  

defang adrese ide ovako: 

johnny5alive[at]gmail[.]com - umesto @ ide [at]




















