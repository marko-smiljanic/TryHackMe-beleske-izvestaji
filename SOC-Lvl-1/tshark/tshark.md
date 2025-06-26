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

`sudo tshark -3 testfajl.pcap`

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

`tshark -r write-demo.pcap -z expert -q`













