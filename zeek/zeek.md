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

**ovde u 'fileds' vidimo kojim sve stvarima mozemo da pristupimo iz log fajla**

`cat dns.log | zeek-cut query | sort | uniq`

- dohvatamo jedinsvtvene dns query-je iz log fajla  

`cat conn.log | zeek-cut duration | sort -n`  

- sortira trajanje konekcije po uzlaznom rednosledu (`-nr` je po silaznom)

### podesetnik za linux komande 

> `cat` je citanje fajla  
`head` je citanje prvih 10 linija  
`tail` je citanje zadnjih 10 linija  
 
> `history` je istorija komandi iz cmd-a  
`!10` izvrsi 10tu komandu iz istorije  
`!!` izvrsi proslu komandu (mada ja ovo resavam sa strelicama na tastaturi)  

>`cat test.txt | cut -f 1` prikazi prvi field  
`cat test.txt | cut -c1` prkazi prvu kolonu  
`cat test.txt | grep 'keywords'` pronadji reci u fajlu  
`cat test.txt | uniq` eliminisi duplikatske linije  








