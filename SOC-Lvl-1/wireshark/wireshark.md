# Wireshark, beleske, vezbanje, zadaci

WireShark je alat koji nije primarno IDS nego samo radi dubinsku analizu i istrazivanje paketa. Ne modifikuje pakete, vec ih samo cita...  
Wireshark je GUI alat.  

otvorimo trazeni fajl kroz wireshark i idemo na statistic > capture file properties i nadjemo flag u komentarima fajla  

u capture file properties vidimo i koji je ukupan broj paketa. Na ovom mestu imamo i hes fajla i mnoge druge podatke   

## disekcija paketa i detalji paketa

wireshark koristi OSI slojeve za razlaganje paketa.  

Kada kliknemo na paket jednom ili dva puta onda dobijemo njegove detalje  

1. Frame sloj: vidimo detlaje; za fizicki sloj OSI modela 
2. Source [MAC] sloj: vidimo izvorne i odredisne MAC adrese; iz Data link sloja OSI
3. Source [IP] sloj: vidimo izvorne i odredisne ipv4 adrese; iz Network sloja 
4. Protokol: pokazuje detalji koji su protokoli korisceni i izvorni i odredisni port; iz trnasportnog sloja
- greske protokola takodje pripadaju 4.tom sloju. Prikazuje specificne segmente iz TCP-a koje bi trebalo ponovo sastaviti
5. Aplication protocol: ovaj sloj pokazuje detalje specificne za koriscene protokole (http, ftp i smb); iz aplikacijskog sloja 
- application data: produzetak 5.og sloja koje nam pokazuje specificne aplikacione protokole i njihove detalje 

kada otvorimo ove slojeve vidimo razlicite informacije  

zadatak je da se istrazi paket... da odgovorimo na pitanja potrebno je istrazivati razlicite stake paketa, koji su uglavnom lako uocljivi  

poslednji zadatak je da se prosle e-tag value. Za to moramo da idemo u http sekciju nadjemo E-tag > desni klik na njega > copy  > value  

**pronalazak paketa:**
- go > go to packet -otvori se meni za pretragu paketa po id-ju  
- edit > find packet -pronadji paket po sadrzaju (pretrage mozemo podesiti da budu osetljiva na velika i mala slova)  

> oznacavanje paketa, ako zelimo da oznacimo nesto na sta treba obratiti paznju... desni klik na paket > mark/unmark

> dodavanje komentara paketa desni klik > packet comment  

> posto wireshark nije IDS nekad je potrebno izvesti pakete na dalju obradu... file > export specified packet 

> takodje postoji i izvoz objekata ali samo za odredjene protokole file > export objects (ovo je znacajno da se otkriju deljene datoteke i za dalju istragu)  

> format prikaza fremena, podrazumevano u wiresharku su postavljene sekunde od pocetka snimanja a mi bi trebali promeniti u UTC date and time of day (view > time display format)  

> analyze > expert information da vidimo poruke i specificna stanja protokola koji mogu da ukazuju na anomalije i probleme  
> ovde moze da se udje i skroz u donjem levom cosku crvena ikonica

**u jednom zadatku se trazi da se istraze komentari paketa**

sa opcijom go to packet pronadjemo paket po id-ju

- u komentaru ovog paketa se nalazi uputstvo da skocimo na drugi paket i istrazimo jpg deo tog paketa (dobijemo id)  
- odemo na jpg i exportujemo na desktop (desni klik na jpg deo paketa i export packet bytes i sacuvamo na desktop)
- kada sliku sacuvamo na desktop idemo kroz terminal do nje i uradimo `md5sum slika.jpg`
- drugi nacin za ovo bez pronalaska paketa preko id-a nego odmah kroz: file > export objects > http > pretrazimo sa jpg i onda vidimo broj paketa 

**potrebno je naci nesto iz nekog .txt fajla **
- file > export objects > odaberemo http > u pretragu kucamo txt > i cuvamo na desktop taj pronadjeni fajl (koji odgovara id-ju paketa), zatim otvorimo i procitamo flag 
- drugi nacin da nadjemo paket po id-ju (paket iz prethodnog zadatka) i nadjemo pod HTTP > line based text data  

**zadatak da se procita koliko ima warning-a**\

- odemo u expert information i prosirimo postojeci prozor da bi mogli da vidimo na desnoj strani ukupan broj za alert koji nas interesuje  

## filtriranje paketa 

wireshark ima mocan mehanizam koji filtrira pakete, koji omogucava suzavanje saobracaj i fokus na dogadjaje koji nas zanimaju  

kliknemo na polje paketa koje zelimo da filtriramo i desni klik > conversation filter

u istom meniju imamo i colorise conversation koji se koristi da oboji i istakne pakete sa primenom filtera i one bez primene filtera. Radi na principu pravila bojenja. Boja na istom mestu moze da se i resetuje  

ove dve opcije mogu da se pokrenu kroz view karticu  

desni klik > pripremi kao filter znaci da kreiramo filter, dodaje upit i ceka komandu za izvrsenje 

analyze > primeni kao kolonu pruza osnovne informacije o svakom paketu (moze se uci i preko desnog klika)  

pracenje strima je opcija koja nam omogucava rekonstruisanje tokova i prikaz sirovog saobracaja kako je predstavljen na nivou aplikacije (moze i preko menija desnog klika ili analyze > follow)  

**pronaci paket 4 i u njemu http i primeniti ga kao filter**

- desni klik na http, primenim ga kao filter (gore u traci gde se kuca tekst vidimo koji je filter query: http)  

**koliko je ukupno ostalo paketa nakon primene filtera**

- to vidimo skroz dole u traci pod 'displayed'

**otici na paket 33790, pratiti http stream i videti odgovore. Proveriti odgovore na veb serveru i odgovoriti kolikko je ukupno umetnika**

- u zadatku kaze da se radi sa: desni klik na paket > follow > tcp stream, ali ja tako ne mogu da nadjem resenje
- radim file > export object... u pretragu za export kucam artist i prikaze se artist.php (proverim da je to taj id paketa koji trazim) i onda sacuvam fajl na desktop. Nakon toga otvorim fajla (sa pluma) i pronadjem koliko ima artista u kodu (artist=1, ...)  

# WireShark Packet Operations 

meni statistika pruza dosta dodatnih opcija: 
- resolved address: prikazuje razresene ip adrese i dns
- protocol hierarchy: prikazuje statistiku koriscenih protokola i portova 
- conversations: prikazuje listu razgovora izmedju dva endopoint-a (ethernet, ipv4, ipv6, TCP, UDP) 
- endopoints: slicno konverzacijama ali prikazuje info za jedno specificno polje. Takodje postoji opcija name resolution da pretvara mac adrese u format citljiv ljudima (dostupno samo za eternet)

takodje postoje opcije za razresavanja ip iu port imena, ali ova opcija mora da se omoguci u edit > preferences > name resolution  

wireshark pruza i mapiranje geolokacije na IP adresu (odredjivanje izvorne i odredisne adrese). Funkciju je potrebno aktivirati na edit > preferences > name resolkution > maxMind database. Ove informacije ce se nalaziti u detlajima IP protokola za podudarne adrese (u endpoints). Da bi se videla geolokacija potrebna je internet veza ali VM za vezbu nema.  

**pronaci ip adresu za hostname koji pocinje sa bbc**

ovo trazimo u statistics > resolved addres i tu imam pretragu da kucam 

**koliko ukupno ima ipv4 konverzacija**

ovo trazimo statistic > conversations i odmah u kartici za ipv4 vidimo broj (samo sacekati da se ucita sve)

**koliko bajtova je prebaceno od micro st mac adrese**

sad odem na statistic > endopints i ukljucim name resolutions i pronadjem mac adresu 

**koji je broj ip adresa povezanih sa kansas city**

prvo moram ukljuciti opciju:  edit > preferences > name resolkution > maxMind database.   

Onda pogledati u endpoints

**koja ip adresa je povezana sa blicnet organizacijom**

edit > preferences > name resolution i ukljucim resolve ip addres (a mogu i transport names)  

iskljucim name resolution da bih video adresu 

## u statistici imamo jos opcija za prikaz

u tabu statistic imamo jos:

- ipv4 ipv6 prikazuje sve opcije za obe verzije ip adresa. Mozemo prikazati sve dogadjaje povezane sa odredjenima dresama u jednom prozoru 
- dns: prikazuje ukupnu upotrebu dns servisa (rcode, opcode, class, query type, query stats)
- http: vidimo kodove zahteva i odgovora na originalne zahteve

**koja je najcesca odredisna adresa**

vidimo u statistic > ipv4 > source and destination adress > zatvorimo surce deo i sortiramo po count prikaz 

**koji je max vreme zahteva i odgovora na uslugu za dns pakete**

statistic > dns i pod service stats nadjemo max vrednost 

**koliki je broj ip zahteva koje je izvrsio rad[.]msn[.]com**

statistic > http > load distribution i malo je teze pronaci za ovu adresu ukupno, jer se pojavljuje na vise ispisa i tesko je prepoznati koje je ukupno 

# Packet filtering - principles 

capture > capture filter je pregled filtera za hvatanje saobracaja  

ovo je najmocnija funkcija wireshark-a. Podrzava 3000 protokla i omogucava pretragu na nivou paketa sa detaljnim pregledom  

pregled filtera analyze > display filters 

operatori za filtriranje su isti kao i u programiranju (!=, ==, &&, || itd.)  

traka sa filterima boji filtere kao vazeci, nevazeci i upozorenje (odnosi se se na rad filtera)  

filteri se kucaju u traku iznad prikaza paketa i tu imamo jos opcija za filter...   

primer ip filtera:  

- ip.addr == neka adresa/24 - prikazi sve pakete koji sadrze ip adrsu ili adrese iz podmreze  
- ip.src  
- ip.dst  

primer tcp/udp filtera:  

- tcp.port == 80 ili udp.port == 80
- tcp.srcport == ili udp.srcport  
- tcp.dstport == ili udp dstport

drugi filteri:  

- http - prikazi sve http pakete  
- dns - prikazi sve dns pakete  
- http.response.code == 200 - prikazi sve http sa 200 OK  
- dns.flags.response == 0 - prikazi sve dns zahteve  
- dns.flags.response == 1 - prikazi sve dns odgovore  
- http.request.method == "GET"  
- dns.qry.type == 1 - sve DNS A zapise  

**wireshark ima opciju analyze > display filter expression. Ovde vidimo detalje za odredjeni protokol i ostale informacije koje se mogu dodeliti nekom filteru**  

**koliki je broj ip paketa**

u polje za fitler unosim samo `ip` i procitam dole broj prikazanih paketa 

**koji je broj paketa sa TTL value less than 10?**

pisem filter: `ip.ttl < 10`  

**koji je broj paketa koji koristi TCP port 4444**

`tcp.port == 4444`

> kad kucam filtere cak mi i izadje pomoc u vidu auto-complete-a

**koji je broj http get zahteva poslatih na port 80re**

ovde moram kombinovati dva upita sa and: `http.request.method == "GET" && tcp.dstport == 80`

**koji je broj type A DNS query-ja**

dns.qry.type == 1 

ovde postoji problem jer meni primenom ovog filtera pokazuje da je resnje 106 (a to nije resenje)  

isti je problem kad apokusam preko analyze > display filter expression i odaberem filter za dns qry type  

resenje je da se primeni i filter za flag response jer nam bez toga trazeni rezultat nije tacan  

**resenje je:**  

`dns.qry.type == 1 && dns.flags.response == 1`

### napredni filteri  

filter contains: http.server contains "Apache" - svi http paketi ciji server sadrzi odredjene reci    

filter matches: http.host matches "\.(php|html)" - svi http paketi ciji hostovi sadrze .php ili .html  

filter in: tcp.port in {80 443 8080} - svi tcp paketi ciji portovi sadrze odredjene vrednosti  

filter upper: upper(http.server) contains "APACHE" - svu http paketi i njihovi serveri to uppercase koji sadrza odredjenu rec  

filter lower: lower(http.server) contains "apache" - isto samo lowercase  

filter string: string(frame.number) matches "[13579]$" - konveruj sve frame number u string vrednosti i navedi frejmove koji zavrsavaju neparnim vrenodstima  

pored polja za unos filtera imamo dugme obelezivac da ih mozemo koristiti vise puta bez ponovnog kucanja, kad kliknemo na to dugme:
save this filter > new display filter  

wireshark profli sluze za pamcenje konfiguracija sto je kosirno za za svaki slucaj istrazivanja koji zahteva drugaciji skup pravila bojenja i dugmadi za filtriranje
edit > configuration profiles > default na desni klik imamo switch to > pa nas novi default profil  

**pronadji sve microsoft IIS servere. koji je broj pakete koji ne poticu sa porta 80**

`http.server contains "IIS" && tcp.srcport != 80`  

**sve microsoft iis servere ciji je broj paketa ima berziju 7.5**

`http.server contains "Microsoft-IIS/7.5"`

**ukupan broj paketak koji koriste portove 3333, 4444, 9999**

`tcp.port in {3333 4444 9999}`

**broj paketa koji je paran TLL**

`string(ip.ttl) matches "[02468]$"`

**promeni profil na checksum control, koji je broj bad tcp checksum paketa**

edit > config profiles > checksum control profile, nakon toga otvorim analyze > display filter expression i kreiram filter pod TCP: tcp checksum status == bad
kreirani filter izgleda ovako: `tcp.checksum.status == 0`

Use the existing filtering button to filter the traffic. What is the number of displayed packets?

**koristi postojece dugme za filtriranje saobracaja, koji je broj paketa sa tim filterom?**

ovo dugme se nalazi odmah sa desne strane na kraju trake-prozora za kucanje filtera, kada se odabere checksum profile, klikom na to dugme treba da dobijemo predefinisani upit  

`(http.response.code == 200 ) && (http.content_type matches "image(gif||jpeg)")`

# Wireshark - traffic analysis  

## nmap scans

nmap skeniranje: skeniranje TCP konekcija, SYN i UDP  

SYN, REST i ACK su nam flagovi koji nam opisuju proces rukovanja otvaranja i zatvaranja tcp portova  

**tcp skeniranje: nmap -sT**  

oslanja se na trosmerni hendshak-e, koriste ga neprivbilegovani korisnici (koji nisu root), obicno velicina veca od 1024 bajta jer zahtev ocekuje neke podatke  

otvaranje tcp porta: syn - syn,ack - ack  
otvaranje tcp porta: syn - syn,ack - ack - rest, ack  
zatvorenui tcp port: syn - rst,ack  

wireshark filter za sleniranje tcp connect-a: `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`
  
**tcp syn skeniranje: nmap -sS**  

nema trosmerno rukovanje, koriste privilegovani useri, obicno je velicina manja ili jednaga 1024 bytes, ne ocekuje se prijem podataka  

otvori tcp port: syn - syn,ack - rst  
zatvori tcp port: syn - rst,ack  

wireshark filter za prikaz TCP SYN skeniranja: `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`  

**udp scan: nmap -sU**

ne oslanja se na trosmerno rukovanje, nema upit za otvorene portove, ICMP poruka o gresci za zatvaranje portova  

otvaranje udp porta: udp paket  
zatvaranje udp porta: udp paket-icmp type3, code 3 messsage (destination unreachable, port unreachable)  

wireshark filter za udp obrasce skeniranja: `icmp.type==3 and icmp.code==3`  


**koji je ukupni broj tcp connect skeniranja**

u wireshark ubacimo trazeni fajl za vezbu...  

primenimo filter za tcp: `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`  

**koji je tip skeniranja koriscen da skenira tcp port 80**

prvo primenimo filter: `tcp.port == 80`  

tu vidimo sablone syn-syn,ack-rst,ack i taj sablon odgovara tcp connect skeniranju 

**koji je broj poruka: zatvoren udp port**

`icmp.type == 3 and icmp.code == 3`

**koji udp port u opsegu 55-70 je otvoren**  

`udp.dstport >= 55 and udp.port <= 70`

kada primenimo ovaj filter videcemo skeniranja koja se vracaju sa unreachable portove, na jednog njih kliknemo i proverimo pod control message protokol koji je port u pitanju  

posto imamo 3 poruke (icmp greske), kada istrazimo svaku dodjemo do toga da su zatvoreni portovi: 69, 57  

onda je preostali port - 68 onaj koji nije vratio gresku. Ovo mozemo da vidimo i u prikazu nakon filtriranja. Skenirani portovi sa greskom su obojeni drugacije.  

nase je samo da pretrazimo portove koji nisu vratili gresku a da su u opsegu 55-70  

## arp poisoning (man in the middle)

arp protokol: radi na lok mrezi, omogucava komunikaciju izmedju mac adresa, nije bezbedan protokol, nije protokol za rutiranje, nema funkciju autentifikacije, uobicajeni obrasci su zahtev odgovor najava i besplatni paketi  

legitiman arp zahtev je kada proveravamo da li neki od dostupnih hostova koristi ip adresu i odgovor od hosta koji koristi odredjenu ip adresu  

zahtev je u wiresharku prikazan sa reci who has [ip adresa], a odgovor je samo [adresa]

wireshark filteri: 

- `arp.opcode == 1` kod 1 arp zahtev  
- `arp.opcode == 2` kod 2 arp odgovor  
- `arp.dst.hw_mac==00:00:00:00:00:00` pretraga, arp skeniranje 
- `arp.duplicate-address-detected or arp.duplicate-address-frame` moguce otkrivanje arp trovanja 
- `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)` moguce arp preplavljivanje zbog detekcije 

sumnjiva situacija je kada postoji dva razlicita odgovora za odredjenu ip adresu. Medjutim pojavljuje se samo druga vrednost u odgovoru ip adrese   

sumnjiva situacija je kada na arp zahtev dobijemo vise odgovora. Kada kliknemo na dogadjaj vidimo da imamo kod koji govori na dupliranu ip adresu  

**koji je broj arp zahteva koje je napravio napadac**  

ubacimo fajl u wireshark koji je za ovaj zadatak...  

prvo kucamo pretragu skeniranja: `arp.dst.hw_mac==00:00:00:00:00:00`  

kada nam ovo izbaci rezultate idemo desni klik na sumnjivu aktivnost i applay as filter > ...and selected. Sa ovim uzimamo mac adresu. Filter sada izgleda ovako `(arp.dst.hw_mac==00:00:00:00:00:00) && (eth.src == 00:0c:29:e2:18:b4)`    

na kraj filtera dodajemo `&& (arp.opcode==1)` da bi smo istrazili samo arp zahteve umnjivog karaktera  

konacan filter izgleda ovako: `(arp.dst.hw_mac==00:00:00:00:00:00) && (eth.src == 00:0c:29:e2:18:b4) && (arp.opcode==1)` i onda vidimo koji je ukupan broj zahteva   

**koliki je broj http paketa koje je napadac primio**

primenimo filter iz prethodnog zadatka. Odaberemo jedan dogadjaj i kliknemo na njega. Ona gledamo njegove detalje Ethernet > source > address i onda na to desni klik > apply as filter > selected  (samo selected ne ...and selected jer ce tad na postojeci upit dodati ovaj)  

filter koji dobijemo sa ovim je: `eth.addr == 00:0c:29:e2:18:b4` i mi na njega rucno dodamo jos and http, tako da je konacni filter:  

- `eth.addr == 00:0c:29:e2:18:b4 && http`

**koliki je broj proverenih unosa username password**

kada rasirimo wireshark prozor do kraja pod info (podaci nad kojim je primenjen poslednji http filter) gledam URI da nadjem neku formu.  

kada sam nasao uri forme vidimo da se radio i POST zahtev. Kada pogledamo u detlajima (pod HTML form url encoded) vidimo uname i pass vrednosti koje su prosledjene  

dalje trazimo pod hypertext transfer protocol > post /userinfo.php desni klik na ovo > apply as filter > ...and selected (da ga zalepi sa and na prethodni filter)  

na kraju filter je: `(eth.addr == 00:0c:29:e2:18:b4 && http) && (frame[54:29] == 50:4f:53:54:20:2f:75:73:65:72:69:6e:66:6f:2e:70:68:70:20:48:54:54:50:2f:31:2e:31:0d:0a)`  

ono sto dobijemo primenom filter pogledamo i vidimo u detalje da li negde ima prikazana lozinka. Negde ima negde ne, potrebno je rucno ici i brojati gde se pojavljuje lozinka da bi smo dali konacan broj

**koja je lozinka od client986**

znaci ostanemo na rezultatu iz prethodnog zadatak i pretrazujemo rucno da vidimo koja je lozinka od rezultata filtriranja. Lozinka se nalazi na poslednjoj stavci u detaljima html form url encoded  

**koji je komentar od client354**

> primenjen je filter iz proslog zadatka `(eth.addr == 00:0c:29:e2:18:b4 && http) && (frame[54:29] == 50:4f:53:54:20:2f:75:73:65:72:69:6e:66:6f:2e:70:68:70:20:48:54:54:50:2f:31:2e:31:0d:0a)`  

obrisemo filter do ovog dela sve, znaci samo ovo ostane `(eth.addr == 00:0c:29:e2:18:b4 && http)`, nakon toga idemo na detalje (tamo gde smo gledali lozinku) i desni klik na html form url encoded apply as filte > and selected  

konacan filter izgleda ovako: `((eth.addr == 00:0c:29:e2:18:b4 && http) ) && (urlencoded-form)`  

- onda na dobijenim rezultatima idemo i gledamo za korisnika client354 trazimo komentar koji je ostavio u toj formi  

## identify host: DHCP, NetBIOS, Kerberos

## DHCP

u poslovnim mrezama se zna unapred odredjeni sablon identifikacije hostova (imena hostova)  

dhcp je protokol za automatsko dodeljivanje ip adresa i drugih parametara komunikacije

wireshark filteri: 

- `dhcp` ili `bootp` 
- `dhcp.option.dhcp == 3` - zahtev, sadrzi informaciju o imenu hosta 
- `dhcp.option.dhcp == 5` - ACK, prihvaceni zahtevi  
- `dhcp.option.dhcp == 6` - NAK, odbijeni zahtevi 
- `dhcp.option.hostname contains "keyword"` - zatev: imena hosta, ip adrese, zakup ip adrese, mac klijenta
- `dhcp.option.domain_name contains "keyword"` - ack: ime domena i dodeljeno vreme zakupa
- nak - preporuka da se cita umesto da se filtrira  (poruka detalji, razlog, odbijanja)

## NetBIOS (NBNS)

omogucava aplikacijama na razlicitim hostovima da medjusobno komuniciraju  

wireshark filter: 

- `nbns`
- `nbns.name contains "keyword"`  

## Kerberos 

podrazumevan za auth microsoft windows domena. Autentifikacija 2 ili vise racunara preko nepouzdane mreze  

wireshark filter:

- `kerberos` 
- `kerberos.CNameString contains "keyword"` `kerberos.CNameString and !(kerberos.CNameString contains "$")` username: vrednosti bez $ su korisnicka imena a kad primenimo $ onda dobijamo imena hostova  
- `kerberos.pvno == 5` `kerberos.realm contains ".org"` `kerberos.SNameString == "krbtg"` ime domena za generisani tiket i client ip adresa. Informacije o adresam su samo u zahtevu paketa 

**pronaci mac adresu hosta "Galaxy A30"**

prvo u wureshark ubacimo trazeni fajl  

primenimo ovaj filter i pod dhcp u detaljima nadjemo mac adresu

`dhcp.option.hostname contains "A30"`

**koliko netbios registracionih zahteva ima radna stanica "LIVALJM"**

da bih sklopio filter moram da idem na analyze > display filter expression > nbns:

- pod filter nbns.flags.opcode idem na == i na  registration i tako smo formirali jedan deo filtera 
- onda opet pod nbns.name odaberemo matches i upisemo vrednost. Ova dva filtera spajamo sa and (&&)  

`nbns.flags.opcode == 5 && nbns.name matches "LIVALJM"`

**koji host je trazio (request) adresu 172.16.13.85**

`dhcp.option.dhcp == 3 && dhcp.option.requested_ip_address == 172.16.13.85`

i onda u detalje idem pod dhcp > option host name i nadjem 

**koja je ip adresa usera u5 (defang format)**

u wireshark ubacujemo drugi fajl  

primenimo filter i pogledamo adresu u detaljima i vratimo kao defang (gde god su . pise se [.], uglavnom je ovako za ip adrese ali ima na CyberChef da se izgenerise)  

`kerberos.CNameString contains "u5"`

**koji hostname je dostupan host u kerberos paketima**

primenimo filter i idemo u detlajie na: kerberos > cname > cname string

`kerberos.CNameString contains "$"`










 
















