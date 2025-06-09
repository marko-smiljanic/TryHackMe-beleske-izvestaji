# Zeek, upotreba i vezbanje  

Zeek je alat koji se koristi za nadzor mreze

`zeek -C -r sample.pcap`  

- citanje pcap fajla pomocu zeek-a  

kada ovo uradimo dobicemo neke log fajlove i citanje tih log fajlova mozemo raditi za komandom `cat`  

kada sa `cat` otvorimo neki log fajl onda cemo moci da vidimo sve sto se nalazi u njemu  

posto je to gomila podataka, na pocetku sadrzi spisak polja na osnovu kojih su grupisani  

`zeek-cat` je komanda pomocu koje izdvajamo odredjene stvari iz log-a (ugradjeno u zeek alat)  

`zeek -C -r sample.pcap`  

- citamo pcap fajl

`cat dhcp.log`

- citanje odabranog log fajla
- ovde u 'fileds' vidimo kojim sve stvarima mozemo da pristupimo iz log fajla

`cat dns.log | zeek-cut query | sort | uniq`

- dohvatamo jedinsvtvene dns query-je iz log fajla  

`cat conn.log | zeek-cut duration | sort -n`  

- sortira trajanje konekcije po uzlaznom rednosledu (`-nr` je po silaznom, ovo je zapravo numericko sortiranje)

*podesetnik za linux komande:*

> `cat` je citanje fajla  
`head` je citanje prvih 10 linija  
`tail` je citanje zadnjih 10 linija  
 
> `history` je istorija komandi iz cmd-a  
`!10` izvrsi 10tu komandu iz istorije  
`!!` izvrsi proslu komandu (mada ja ovo resavam sa strelicama na tastaturi)  

> `cat test.txt | cut -f 1` prikazi prvi field  
`cat test.txt | cut -c1` prkazi prvu kolonu  
`cat test.txt | grep 'keywords'` pronadji zadate reci u fajlu  
`cat test.txt | uniq` eliminisi duplikatske linije  
`cat test.txt | wc -l` izbroj broj linija  
`cat test.txt | nl` prikazi broj linija

> `cat test.txt | sed -n '11p'` isprintaj liniju 11  
`cat test.txt | sed -n '10,15p'` isprintaj liniju izmedju 10 i 15  
`cat test.txt | awk 'NR < 11 {print $0}'` isprintaj sve ispod 11 (ako je `==` onda to znaci isprintaj tu liniju)  

> filtriranje, sortiranje i printanje specificnih stvari iz logova pomocu `zeek-cut` smo videli gore  

> `sort | uniq` izvadi duplikati (`-c` pokazi koliko je bilo duplikata)  
`rev` uradi reverse string karatkera  
`cut -d '.' -f 1-2` razdvoji print po svakoj . i printuj prva dva polja  
`grep -v 'test'` prikazi linije koje ne odgovaraju prosledjenoj reci, ako se doda `-v -e` onda mozem oda nabrajamo vise reci  
`file` prikazuje informacije o fajlovima  
`grep -rin Testvalue1 * | column -t | less -S` pretrazi string testvaule svuda i organizuj razmak u kolonama i prikazati ka manjem

# Zeek-signatures

slicno kao snort pravila. Razlika je sto zeek potpisi nisu primarna detekcija kao kod snorta.  

`zeek -C -r sample.pcap -s sample.sig` ovako se primenjuje potpis (-C znaci ignorisi greske kontrolne sume)  

*primer jednostavnog potpisa:*  

detektovanje http lozinki u cistom tekstu

```
signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}

# signature: Signature name.
# ip-proto: Filtering TCP connection.
# dst-port: Filtering destination port 80.
# payload: Filtering the "password" phrase.
# event: Signature match message.
```

zeek podrzava regex  

pravil oza filtriranje ftp saobracaja. Cilj je da se otkriju pokusaji prijavljivanja na ftp kao adminsitrator

```
signature ftp-admin {
     ip-proto == tcp
     ftp /.*USER.*dmin.*/
     event "FTP Admin Login Attempt!"
}
```
pokusaj nasilnog neuspeha prijavljivanja

```
signature ftp-brute {
     ip-proto == tcp
     payload /.*530.*Login.*incorrect.*/
     event "FTP Brute-force Attempt"
}
```

u jednom signatures fajlu moze da bude vise potpisa 

### Zadaci:

### z1:

u zadatku se trazi da se kreira HTTP signature pravilo i pronadje source adresa prvog dogadjaja. 

kreiram http pravilo:

```
signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}
```  

`zeek -C -r http.pcap -s http-password.sig` 

- primenim pravilo...

`cat signatures.log | zeek-cut src_addr` 

- otvorim fajl da vidim kako se zove field za source adresu (ili preko `head imefajla.log` pretrazim u cmd), i onda pomocu zeek-cut isecem potreban podatak (source adresa)  
- mogu pored source adrese da prikazem i poruku `cat signatures.log | zeek-cut event_msg src_addr`  

`cat signatures.log | zeek-cut src_port` 

- provera koji je source port na drugom dogadjaju (prikazem sve source portove i pogledam drugi po redu)  

`cat conn.log | zeek-cut orig_pkts resp_pkts id.orig_p` 

- pronalazak ukupnog broja poslatih i primljenih paketa od izvornog porta 38706. Ovo pokrenem i nadjem odgovarajuci port, pogledam brojeve i saberem primljene i poslate

### z2

kreiranje globalnog pravila i ispitivanje notice.pcap  

kada udjemo u .sig fajl vidimo da treba da dovrsimo zapoceta pravila...

```
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
    payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}
```

`zeek -C -r ftp.pcap -s ftp-bruteforce.sig` 

- primenimo pravila...  

`head notice.log` 

- proveravam zaglavlja log fajla da bih video koje polje mi najbolje dohvata ceo dogadjaj (uid)  

`cat notice.log | zeek-cut uid | sort | uniq | wc -l` 

- proverimo notice.log za sve unique dogadjaje   

`cat signatures.log | zeek-cut event_msg | grep "FTP Brute-force Attempt!" | wc -l` 

- ovde trazim koji je broj ftp brute force signature poklapanja.  
u ovom slucaju pretrazujem signatures.log tako sto uradim cut na message (poruka koja se prikaze kada se opali brute force dogadjaj). Pogledam u pravilima koja je poruka za dogadjaj i samo prikazem njen broj poklapanja sa grep-om  

# Zeek Scripts - primena skripti na .pcap fajlove 

zeek skripte imaju ekstenziju .Zeek  

lokacija zeek skripti je:

> `/opt/ zeek /share/ zeek /base` ovo su osnovne skripte i **nisu namenjene da se menjaju!!** 
> `/opt/ zeek /share/ zeek /site` korisnicki generisane ili izmenjene skripte 
> `/opt/ zeek /share/ zeek /policy` skripte smernica 
> `/opt/ zeek / share/ zeek /site/local.zeek` konfiguraciona datotetka
> pozivanje skripti u rezimu pracenja uzivo `load @/script/path` `load @script-name`

build-in funkcije i skripte 

> ```
> /opt/zeek/share/zeek/base/bif
> /opt/zeek/share/zeek/base/bif/plugins
> /opt/zeek/share/zeek/base/protocols
> ```  

`zeek -C -r smallFlows.pcap dhcp-hostname.zeek`

- ovako se pokrece skripta  

### z1

`zeek -C -r smallFlows.pcap dhcp-hostname.zeek` pokrenem skriptu za pcap fajl  

`cat dns.log` 
- i pronadjem domen value za vinlap01 host, moze i direktno sa cut da se trazi domen ali ovako je jednostavnije, samo pogledati 

### z2

za drugi primer se trazi isto samo sto moram da profiltriram rezultat jer trazim unique hostnames  

`zeek -C -r bigFlows.pcap dhcp-hostname.zeek` pokrenem skriptu nad pcap fajlom  

`cat dhcp.log | zeek-cut host_name | sort | uniq | wc -l` 

- ovo je komanda koja priakze broj 18, ali to nije resenje.  
treba da sklonim `wc -l` i onda da izbrojim rucno i tu vidim da je za jedan host stavljena samo '-' , odnosno za jedan izlistan host nema vrednosti, tako da je resenje 17... glupost koja me ukoci na pola sata...  
**umesto da se fokusiram na bitne stvari ja pola sata trazim da li je broj poklapanja 17 ili 18... neki primeri su bas napravljeni da oduzmu vreme bez potrebe**

`cat dhcp.log | zeek-cut domain` pronalazak domen name-a  

# Zeek Scripts - pisanje skripti 

skripte bi trebalo da se koriste u kombinaciji sa potpisim  

u skripti moze da se filtrira rezultat i kontrolise output  

sadrzaj skripte moze da se prikaze sa `cat`

proste skripte izgleda ovako 

```
event new_connection(c: connection)
{
	print ("###########################################################");
	print ("");
	print ("New Connection Found!");
	print ("");
	print fmt ("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);
	print fmt ("Destination Host: resp: %s # %s <---", c$id$resp_h, c$id$resp_p);
	print ("");
}

# %s: Identifies string output for the source.
# c$id: Source reference field for the identifier.
```

```
event signature_match (state: signature_state, msg: string, data: string)
{
if (state$sig_id == "ftp-admin")
    {
    print ("Signature hit! --> #FTP-Admin ");
    }
}
```

zeek sadrzi lokalne, osnovne skripte koje se nalaze u `/opt/ zeek /share/ zeek /base`  

ucitavanje svih osnovnih skripti je pokretanjem `local` komande  

`zeek -C -r ftp.pcap local`  pokretanje svih lokalnih skripti  

`zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek` 

- pokretanje i provera zeek-ove gotove skripte za brute force na FTP. Provera se radi sa `cat notice.log | zeek-cut ts note msg`  

 
### z1 

`zeek -C -r sample.pcap 103.zeek` primena skripte 

`cat conn.log | zeek-cut uid | wc -l` 

- ocitavanje koliko ima novih konekcija detektovanih skriptom  


### z2 

> napomena: koristim `head logfajl.log` i `cat logfajl.log` da bih video koja sve zaglavlja fajl ima i generalno strukturu koja mi pomaze da znam po cemu neke atribute iz zadatak da trazim  

`zeek -C -r ftp.pcap -s ftp-admin.sig 201.zeek` primena potpisa i skripte na jedan fajl

`cat signatures.log | zeek-cut uid | wc -l`

- broj koliko je bilo poklapanja sa signature (izbrojim svaki dogadjaj zasebno, a to je preko jedinstvenog id-ja: uid)

`cat signatures.log | grep "administrator" | wc -l`

- pronalazi koliko je bilo adminstrator username-ova detektovano  
meni je lakse da se ovo odradi sa grep, jer samo admin ne moze da nadje jer ih ima dosta vise, trazi se jasno nagleseno 'administrator'  

### z3

`zeek -C -r ftp.pcap local` ispitati pcap fajl sa svim lokalnim skriptama  

`cat loaded_scripts.log | zeek-cut path | wc -l` 

- pronaci koliko je ukupno skripti ucitano  
ovo radim tako sto vidim da svaka skripta ima svoj zaseban header 'path' i onda samo njega izbrojim  

### z4

`zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek`

- provera sa pcap fajla sa skriptom koja se nalazi na putanji 

`cat notice.log | zeek-cut uid | wc -l`

- istrazivanje log fajla i pronalazak ukupnog broja brute force napada

# Zeek Frameworks

`zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek` izvrsavanje skripti (konkretno ova je za hesovanje)

`zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek` izvrsavanje skripti za izvlacenje svih fajlova (automatski se kreira folder extract_files)

> `/opt/zeek/intel/zeek_intel.tx` lokacija za intel podatke

### z1

treba primeniti inteligence skriptu i pronaci drugo resenje iz intel log fajla (odakle su informacije?)

`zeek -C -r case1.pcap intelligence-demo.zeek` 

`cat intel.log` provera sta se nalazi u fajlu 

`cat intel.log | zeek-cut seen.where` pregled zaglavalja seen where i pogledamo drugi rezultat

`cat http.log | zeek-cut uri` pregled http.log fajla i pronalazak imena skinutog .exe fajla

`zeek -C -r case1.pcap hash-demo.zeek` primena hash demo skripte 

`head files.log` mogao sam i sa cat, gledam kako je upisan field za md5 hash

`cat files.log | zeek-cut md5` da pronadjem koja je md5 hes vrednost za .exe fajl

`zeek -C -r case1.pcap file-extract-demo.zeek` primenjujemo skriptu za ekstraktovanje fajlova 

`cd extract_files` pokretanje ove skripte stvara folder u kome su fajlovi i zato se moram prebaciti 

`cat extract-1561667874.743959-HTTP-Fpgan59p6uvNzLFja` citam sadrzaj tekst fajla 

# Package manager

zeek package manager pomaze da instaliramo skripte i plugine. komanda kojim se manipulise je `zkg`. (obavezna root privilegija)  

`zkg list` izlistava sve pakete 

> napomena: pozivanje zeek skripti (paketa) moze da bude:  
> pozivanje direktno, pozivanje preko putanje i preko imena paketa 

```
zeek -Cr http.pcap sniff-demo.zeek 
zeek -Cr http.pcap /opt/zeek/share/zeek/site/zeek-sniffpass
zeek -Cr http.pcap zeek-sniffpass 
```

### z1 

`zeek -Cr http.pcap zeek-sniffpass` primenjujem paket 

otvorim notice log kroz `cat` i istrazujjem kako da dodjem do username-a...  

vidim da se username ne pominje u fields vec u purukama (messages)  

`cat notice.log | grep "user" | sort` 

- pristupam sa obicnim grepom jer mi je tako najlakse bilo, verovatno se ovo trebalo odraditi sa `zeek-cut` i da gadjam field msg...  
**zapravo ovako mi ispise bolje...** `cat notice.log | zeek-cut msg | sort`

### z2

`zeek -Cr case1.pcap geoip-conn` pokrecem geo skriptu

`cat conn.log | zeek-cut geo.resp.city | sort` dobavljam koji je grad u pitanju

`cat conn.log | zeek-cut geo.resp.city id.resp_h` dobavljam i ip adresu svakog grada

### z3 

`zeek -Cr case2.pcap sumstats-counttable.zeek` ovo pokrenem i vidim koliko razlicitih status code-a ima


# Zeek prakticni zadaci i vezbe

moram obratiti paznju u gde se nalaze fajlovi za odredjene zadatke 

## z1 - DNS sumnjiva aktivnost 

detektovan je alarm za losu dns aktivnost  

ovde se koristi obican zeek citac .pcap vajlova  

**pronaci pojave ipv6 adrese** 

`zeek -C -r dns-tunneling.pcap` izvrsavamo zeek nad pcap fajlom 

`cat dns.log | head -n 10` uzimamo prvih 10 linija iz fajla da vidimo strukturu

`cat dns.log | zeek-cut qtype_name | sort | uniq -c` 

- trazimo jedinsvene pojave po field-u qtype_name. Kada nam izlista sve brojeve pojava, trazimo AAA pojavu koja oznacava ipv6 adresu

**dohvatiti koliko je trajala najduza konekcija**

`head conn.log` da vidimo koji field ce nam odgovarati 

`cat conn.log | zeek-cut duration | sort -n`

- dohvatamo atribut duration

**treba pronaci domene koji nisu cisco-update.com**

ovako nesto predlaze THM platforma...

```
cat dns.log | head -n 10
cat dns.log | zeek-cut query
cat dns.log | zeek-cut query | cut -d '.' -f 2-3 
cat dns.log | zeek-cut query | cut -d '.' -f 2-3 | uniq -c
cat dns.log | zeek-cut query | cut -d '.' -f 2-3 | sort | uniq

```

a ovako bih ja resio, jer mi je jednostavnije, ali nisam ni shvatio najbolje sta oni tu hoce od mene, da izbrojim domene koji nisu cisco.com ali njih ima puno, a resenje je 6...  

`cat dns.log | zeek-cut query | grep -v "cisco-update.com" | sort  | uniq -c`

- `-v` znaci obrnuta pretraga, vrati sve ono sto ne sadrzi ciscov domen 

**pronaci adresu hosta koji salje previse dns query-ja na isti domen**

`cat dns.log | head -n 10` gledam koji field odgovara za source adresu 

`cat dns.log | zeek-cut id.orig_h | sort | uniq`

- pronalazim ip adresu source hosta

## z2 - Phising 

ovde vidim da imam na raspolaganju skriptu koja je data u folderu zadatka (file extract i hash demo)  

`zeek -Cr phishing.pcap` citam pcap da dobijem logove 

**trazi se ip adresa napada i zbog toga se fokusiram na `conn.log` fajl**  

`cat conn.log | head -n 10` gledam zaglavlja iako znam da je atribut za adresu id.orig_h 

`cat conn.log | zeek-cut id.orig_h | sort | uniq`

- bez uniq vidim da ima gomila adresa ali kad stavim uniq vidi se da je sve doslo sa jedne adrese

*sada odem na cyberchef github i uradim defang adrese (defang je bezbedan zapis kako adresa ne bi bila klikabilna)*  

defang za ovu adresu izgleda ovako: 10[.]6[.]27[.]102

**istraziti http.log i pronaci koja je source adresa malicioznog fajla** 

`cat http.log | zeek-cut source filename` 

- ovde prikazujem adresu i pored ime fajla kako bi bilo lakse pregledno

**proveriti http.log i pronaci sa kojeg domena je maliciozni sajt**

`cat http.log | zeek-cut host uri | sort`

- isecam adresu i uri i tu vidim dosta informacija 

**treba da izvadim hes md5 malicioznog fajla i proverim na virus total, za to cu koristiti prilozenu skriptu `hash-demo.zeek`**

`zeek -Cr phishing.pcap hash-demo.zeek` 

- kada izvrsim skriptu dobijem *files.log*

`cat files.log` da pogledam sta se uopste nalazi u fajlu 

`cat files.log | zeek-cut mime_type filename md5` 

- gledamo files.log i vadimo sve md5 hes vrednosti 

kada dobijem hes, biram ovaj iz msword fajla i proveravam na virus total (trazim u relations sa cime je ovaj fajl povezan). **U relaciji je sa VBA tipom fajla**  

na virus total za docexec trazim kako se zove fajl. To je prvi podatak koji mi ispadne kada ukucam hes u pretragu. **PleaseWaitWindow.exe**  

kroz virus total proveravam .exedoc fajl idem behaviour > dns resolutions i uradim defang uz pomoc cyberchef-a. Problem je sto ima puno stavki i resenje je **hopto[.]org**  

**treba dohvatiti ime malicioznog fajla** 

`cat http.log | zeek-cut uri` 

- exe fajl (knr.exe)  
ovo sam video i pre kad sam istrazivao http.log i files.log. Uri daje dosta razlicitih informacija.

## z3 Log4J

`zeek -Cr log4shell.pcapng detection-log4j.zeek` primenjujem skriptu za pcapng fajl 

**nakon izvrsene skripte proveriti signatures fajl i videti koliko je poklapanja ukupno** 

`cat signatures.log | zeek-cut uid`

**pronaci alat koji je koriscen za skeniranje. Citati http.log fajl. Gadjam field user_agent**  

`cat http.log | zeek-cut user_agent` 

**pronaci koja je ekstenzija ekspoita**  

`cat http.log | zeek-cut uri | uniq`  

**pronaci koji fajl je kreiran uz pomoc base 64 enkodovane komande. Istraziti log4j fajl** 

`cat log4j.log | head -n 10` istrazujem koji je sastav i kakva su zaglavlja log4j fajla

`cat log4j.log | zeek-cut uri | uniq` 

- vidim da ima ukupno 3 komandi, redom dekodujem i trazim detalje o komandi za pravljenje fajlova `touch`  


