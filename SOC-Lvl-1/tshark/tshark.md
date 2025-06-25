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

capture filteri: 

filteri za adresu i port:   

- `tshark -f "host 10.10.10.10"` filtriranje hosta  
- `tshark -f "net 10.10.10.0/24"` filtriranje mreznog opsega  
- `tshark -f "port 80"` filtriranje porta   
- `tshark -f "portrange 80-100"` filtriranje opsega portova  

filteri za izvorne i odredisne adrese:  

- `tshark -f "src host 10.10.10.10"` filtriranje izvorne adrese
- `tshark -f "dst host 10.10.10.10"` filtriranje odredisne adrese 

filtriranje po protokolu:  

- `tshark -f "tcp"`
- `tshark -f "ether host F8:DB:C5:A2:5D:81"` filtriranje mac adrese 
- `tshark -f "ip proto 1"` filtriranje ip protokola 1 (broj jedan je za icmp protokol - lista svih dodeljenih brojeva protokolima: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)   

primer za simulaciju dogadjaja + filtriranje:  

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

**zadaci se pokrecu u terminator terminalima**

terminator terminal omogucava da imam vise podeljenih terminala u istom prozoru, olaksava rad na vise zadataka istovremeno, komanda za pokretanje je `terminator`    

**koji je broj paketa sa SYN bajtovima**

syn flag je za pocetak tcp konekcije, wc -l broji koliko ima takvih paketa    

prvo kucamo komandu za terminator:  

`terminator`

`tshark -r demo.pcapng -Y “tcp.flags.syn == 1” | wc -l`





























