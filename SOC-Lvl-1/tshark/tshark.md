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

`tshark -r demo.pcapng` citanje fajla   
`tshark -c 10` zaustavi snimanje saobracaja nakon 10 paketa  
`tshark -w file.pcap` zapisi snimnjeni saobracaj u fajl   
`tshark -V` detaljne informacije za svaki paket (ova opcija je slicna detaljima iz wireshark-a)  
`tshark -q` silent mode - obustavljanje slanja paketa na terminalu  
`tshark -x` prikaz bajtova paketa u hex i ascii 


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

























