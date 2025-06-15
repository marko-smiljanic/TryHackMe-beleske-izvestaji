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































