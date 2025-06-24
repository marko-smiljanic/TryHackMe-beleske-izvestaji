# TShark beleske i vezbanje 

tshark je CLI alat i sluzi za detaljnu analizu pakete i automatizaciju pomocu skripti

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



























