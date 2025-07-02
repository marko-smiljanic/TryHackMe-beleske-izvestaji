# Brim - beleske i vezbanje

primarna funkcija je obradjivanje pcap datoteka i datoteka logova - pregled i analitika  

koristi zeek format za obradu logova i podrzava zeek potpise i suricata pravila za detekciju  

Brim smanjuje vreme i trud koji su potrebni za obradu velikih (preko 1gb) pcap fajlova (zeek je za velike pcap fajlove jos bolji ali je CLi aplikacija)

Brim je GUI aplikacija. Nesto kao zeek ali gui.  

Brim radi i sa query-jima. Pomocu upita dobavljammo razne stvari iz pcap fajlova.   

Brim query izrazi su slicni kao zeek-ovi. Isto se pristupa field-ovima u fajlovima ali se prvo npr: `_path=="http"` kako bi znali koji fajl gledamo. Query se pise u polje za pretragu  

U prikazu aplikacije sa strane pod tabom query imam vec predefinisane query-je koje mogu koristiti ili modifikovati i koristiti  

**napisati query koji dobavlja ukupan broj identifikovanih imena gradova iz conn.log fajla**  

`_path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city`

**koji je signature id od alerta kategorije: "Potential Corporate Privacy Violation"**

`event_type=="alert" | count() by alert.severity,alert.category, alert.signature_id | sort count`

- u gui aplikaciji kliknem sa strane u query tabu da mi ispise alerts by category ali ga ja dodatno modifikujem i dodajem ovo za id.

> U brim query mozemo koristiti:

> - Osnovna pretraga: bilo koji string ili num vrednost. (pronaci logove koji sadrze neku ip adresu, itd.)
> - logicki operatori or/and/not (npr. pronaci tri cifre u ip i kljucne reci ntp)
> - vrednosti za neko polje: "naziv" == "vrednost" (npr. id.orig_h==192.168.121.40)
> - sadrzaj odredjene log datoteke (_path=="conn.log")
> - brojanje vrednosti polja (count () by_path)
> - sortiranje (count () by_path | sort -r)
> - isecanje odredjenog fielda (_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h)
> - jedinstvene vrednosti (nesto... | uniq)

neki od upita: 

*pronalazak liste komunikacijskih hostova*   
Ovo omogucava pronalazak krsenja pristupa, pokusaje eksploatacije i infekcije zlonamernim softverom

`_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq`

*pronalazak frekventno komonicirani hostovi*  
Kada se identifikuje koji hostovi najcesce komuniciraju jedni sa drugima, mozemo otkriti kradje podataka, eksploataciju i backdoor aktivnosti 

`_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r`

*pronalazak najjaktivnijih portova*  
Napadacima je nemoguce da sakriju tragove paketa. Ovo istrazivanje omogucava da se otkriju dobro skriveni napadi i anomajlije fokusirajuci se na koriscene servise i transport podataka  

```
_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count
_path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r 
```

*otkrivanje dugih konekcija*  
otkrivanje dugih konekcija moze biti prvi indikator backdoor-a

`_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration`

*ispitivanje prenetih podataka*  
ispitivanje moguce kradje podataka radnje poput preuizmanja i sirenja malicioznog softvera

`_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes`

*DNS i HTTP upiti*  
identifikacije sumnjivih veza i zahteva nekog domena 

```
_path=="dns" | count () by query | sort -r
_path=="http" | count () by uri | sort -r
```

*sumnjivi hostname-ovi*  
pomoc pri oktrivanju laznih hostova. Ispituju se DHCP logovi

`_path=="dhcp" | cut host_name, domain`

*sumnjive ip adrese*  
filtriranje omogucava lakse upravljanje

`_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r`

*otkrivanje fajlova*  
uglavnom se uporedjuju hes vrednosti 

`filename!=null`

*SMB aktivnosti (server message block)*  
`_path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"`

*obrasci*
upozorenja koja se generisu, uglavnom sluzi da vidimo na koji deo loga se treba fokusirati
`event_type=="alert"` or `_path=="notice"` or `_path=="signatures"`

# Prakticni zadaci, scenariji

## z1: malware C2 detection

u brim ubacujemo odgovarajuci .pcap fajl 

**pokrecemo query da vidimo sa kojim hostom se najvise komunicira**  

`_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, service | sort  | uniq -c | sort -r count`

- vidimo da je napadnut dns i imamo dve sumnjive adrese, nista nije sumnjivo u brojevima portova  

**dalje, pretrazujemo domene**

`_path=="dns" | count() by query | sort -r`

- sumnjivi domen je ovaj prvi sa najvise pristupa i njega proveravamo na virus total i vidimo da je problem  

**u virus total vidimo u relations da je u vezi sa vise ip adresa, i sad moramo pretraziti i za njih da vidimo da li ima nesto**  

`_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri` 

- vidimo da se sa jedne adrese uradio download .exe fajla, i tu adresu proveravamo u virustotal...  
kada smo proverili vidmo da je je organizacija cobalt strike i vidimo sve informacije vezano za fajl

**sa Suricata ispitujemo alerte kako bi smo zaokruzili pretragu**

`event_type=="alert" | count() by alert.severity,alert.category | sort count`

- **vidimo takodje i da ima alert: network trojan detected. Kada pretrazimo ovu poruku "A Network Trojan was detected" vidimo da je povezan sa drugom adresom**   
tu adresu istrazimo na virus total i vidimo da je to za cobalt strike 

- ovde mozemo videti ukupan broj registrovanih interakcija za svaki alert  
ili zbog preciznosti pretraziti sa `_path=="conn" id.resp_h==104.168.44.45 id.resp_p==443 | count() by id.resp_p` ovde pretrazujemo glavnu otkrivenu ip adresu vezanu za cobalt strike 

*preporucuje se da istrazimo sve kategorije alarma jer cemo tako biti sigurniji ako je bila druga C2 komunikacija (sto obicno i jeste)*  

daljom analizom sumnjivih domena nalazimo ouldmakeithapp[.]top. Ovo je bilo tesko uocljivo jer je imao samo jednu interakciju u prikazu dns  

## z2: crypto mining 

prebacujemo se na odgovarajuci pcap fajl

**prvo pogledati dostupne log fajlove i cesto povezane hostove**

`count() by _path | sort -r`  ovde vidimo da nemamo mnogo log datoteka na raspolganjju  

`_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r`

fokusiramo se na adresu koja nam privlaci paznju (192.xx)  

**gledamo brojeve portova i dostupne usluge pre fokusiranja na ip adresu**

`_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count`

vidimo visestruko koriscenje portova koje nije uobicajeno. 

**sada gledamo prenete bajtove i njihovde velicine**

`_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes`

vidimo masivan broj saobracaja koji potice sa jedne sumnjive ip adrese 

**ispitujemo suricata logove za lako dostupne informacije**

`event_type=="alert" | count() by alert.severity,alert.category | sort count`
 
vidimo da je detektovan crypto mining. Znaci neko sa nase masine radi mining kripto valuta 

**trazimo sve konekcije sa nasom masinom**

`_path=="conn" | 192.168.1.100`

zatim treba provuci sumnjivu adresu (ali odredisnu) kroz virus total, treba ubosti tacno medju masom adresa  

detektovan je server za rudarenje, tesko ce se iz prve pogoditi, tako da je nephodno proveriti i druge adrese...  

**koristimo suricata query da otkrijemo mapirane mitre tehnike**

`event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c`


**koliko ima konekcija sa portom 19999?**

`_path=="conn" | id.resp_p==19999 | count() by id.resp_p`

**koje je ime servisa koji koristi port 6666?**

`_path=="conn" | id.resp_p==6666 | cut service | uniq`

- ako nisam siguran koje polje mi treba onda otkucam sve do cut, da mi izbaci sa tim portom, i idem na details i trazim atribute sta bi mi odgovaralo  

**koji je ukupni iznos bajtova koji je razmenjen sa 101.201.172.235:8888?**

uzmem onaj upit za racunanje ukupnih bajtova i modifikujem ga da prikazuje za ovu adresu i port (izbacim sort)  

`_path=="conn" | put total_bytes := orig_bytes + resp_bytes | 101.201.172.235 | 8888 | cut uid, id, orig_bytes, resp_bytes, total_bytes`

**koji je detektovani mitre tactic id?**

setimo se alerta, kucamo njega u pretragu i onda gledamo detalje  

alert je: Crypto Currency Mining Activity Detected, i kad to ukucam vidim detalje... a moze da se uradi i sa upitomn `event_type=="alert" | cut alert.metadata.mitre_tactic_id | uniq`  


## NAPOMENA: za z1 sam radio screenshot, za z2 nisam, mrzelo me, i ovako mi je uzelo previse vremena 


