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













