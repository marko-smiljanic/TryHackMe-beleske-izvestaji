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

- otvorim fajl da vidim kako se zove field za source adresu (ili preko head pretrazim u cmd), i onda pomocu zeek-cut isecem potreban podatak (source adresa)  
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

# Zeek Scripts

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
















