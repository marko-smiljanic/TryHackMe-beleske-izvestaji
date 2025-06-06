# PCAP citanje, analiza i primena pravila  

fokus snorta je na detekciju i prevenciju upada u mrezu (IDS/IPS)
moze da radi u: 

-live sniffing modu (detektuje pretnje u realnom vremenu)  
-da detektuje i alarmira  
-radi u cmd, nema gui  
-moze da cita logove i paket analize (.pacp fajlove)  

dakle: Snort je dizajniran za aktivnu detekciju u realnom vremenu. Prati mrežni saobraćaj, koristi pravila da prepozna napade, i može odmah da alarmira ili čak blokira sumnjive aktivnosti (ako se koristi kao IPS).
 
### Ovo su komande koje se koriste za zadatke (kroz cmd odemo u folder gde su nam fajlovi za zadatke):

`alert tcp any any <> any 80 (msg: "NADJEN PORT"; sid:100001; rev:1;)`

- pravilo koje detektuje sve portove 80 na tcp, sledeci zadatak sa portom 21, sve isto	

`sudo snort -c local.rules -r mx-3.pcap`

- primena pravila na pcap fajl: primenjujemo pravila koja se nalaze u istom folderu na fajl mx-3

`sudo snort -r snort.log.1748022673 -n 63`	

- snort u rezim citanja: proveravamo kreirani log za prvih 63 paketa.  
citanje moze i preko tcpdump (-X više detalja)
			
`strings ftp-png-gif.pcap | grep -ia ftp`

- iz binarnih fajlova izvlacimo korisne informacije (`-i` case insensitive, `-a` obradi binarne fajlove kao tekstualne i filtrira sve linije koje sadrže ftp )
	
`strings ftp-png-gif.pcap | grep -iac "530 User"`

- nadji sve neuspesne logove (poruka koja se trazi je 530 user)  
poruka: 230 user je uspesno logovanje, to je sledeci zadatak  
poruka: 331 Password detektuje ftp login pokusaje kada se unese validan username, ali password ne  
	
`strings ftp-png-gif.pcap | grep -ia "331 Password" | grep -ic "Administrator"`

- nadji sve logove kada se bio unet validan username, ali password ne (username koji se trazi je "administrator")

**Umesto kroz konzolu ovo sve moze da se uradi preko snort-a i pisanjem pravila, ali je meni bilo lakse da radm sa strings direktno kroz cmd:**

`alert tcp any any <> any 21 (msg:"nadjen port 21!!!"; content:"Administrator";content:"331 Password";nocase; sid:100001; rev:1;)`

- u ovom pravilu se dodaje jos jedan content i za svaki slucaj stavljamo nocase da ignorise velika i mala slova

`alert tcp any any <> any any (msg: "PNG file pronadjen!!!"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid: 100001; rev:1;)`

- pravilo koje detektuje PNG fajl (traži binarni zapis za PNG, tj. pretrazuje binarno fajl dok ne nadje poklapanje):

`sudo snort -c local.rules -r ftp-png-gif.pcap -X -l .`

- primena pravila i logovanje  
`-l .` znaci da se kreira log fajl na trenutnoj lokaciji u cmd gde se nalazimo

`sudo snort -r snort.log.1748285776 -X`

- rezim citanja loga, `-X` je prikaz sa vise detalja

`alert tcp any any <> any any (msg: "gif file pronadjen!!!"; content:"GIF8"; sid: 100001; rev:1;)`	

- pravilo za pronalazak GIF fajlova  
prvi nacin: nalazi sve gif fajlove nezavisno od tipa

```		
alert tcp any any -> any any (msg:"GIF87a file detected"; content:"GIF87a"; sid:1000004; rev:1;)
alert tcp any any -> any any (msg:"GIF89a file detected"; content:"GIF89a"; sid:1000005; rev:1;)
```
	
- drugi nacin (sa dva pravila):  
ovako je mozda najlakse jer samo idem kroz alert fajl i pratim poruke koji je tip gif fajla

`alert tcp any any <> any any (msg: "torrent file pronadjen!!!"; content:".torrent"; sid: 100001; rev:1;)`

- pravilo za detekciju torrent paketa:  
napomena: u alert delu (u konzoli) odmah nakon izveštaja ili u alert fajlu mogu da se pogledaju rezultati.

`alert tcp any any -> any any (msg:"primer"; dsize:770<>855; sid:1000001; rev:1;)`

- pravilo koje trazi pakete odredjene velicine (od-do)

`KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=`

- Komanda koju je izvršio napadač je u base64 i treba je prevesti (ovakve informacije se vide u detaljnom prikazu paketa):
	
# LIVE ATTACK  

### Zad 1: Uzivo snimanje i sprecavanje bruteforce napada

`sudo snort -dev -l .`

- stavljamo snort u sniffer mode i pravimo log fajl

`sudo snort -r imelogfajla`

- log mode, citanje log fajla

`sudo snort -r imelogfajla 'port 22' -n 10`		

- filtriramo citanje log file samo na port 22 i uzimamo prvih 10

> Default lokacija snorta i njegovih pravila: /etc/snort/rules/local.rules

`drop tcp any 22 <- any any (msg: "blokiran ulazni saobraćaj na portu 22 zbog bruteforce napada", sid: 100001; rev:1;)`

- pravilo za odbacivanje ulaznog tcp saobracaja po portu 22

`sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`

- koristim konfiguracioni fajl za pokretanje pravila (kroz .conf fajl se ukljućuju i lokalna pravila).  
alternativa: sudo snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.conf -A full -q


Iz nekog razloga ove komande meni nece da rade !!!  Pokretanje snorta sa alarmom u direktno u terminalu:  
*sudo snort -A console -q -c /etc/snort/snort.conf -i eth0*   
*sudo snort -A full -q -c /etc/snort/snort.conf -i eth0*     


### Zad 2:  Analiza i blokiranje odlaznog saobraćaja

```
***A**** znači da je TCP flag ACK uključen.
******S* znači da je TCP flag SYN uključen (inicijacija veze).
***AP*** znači ACK i PUSH flagovi su uključeni (prijenos podataka). 
```

**U paketima vidimo oznake (znaci neki transfer se desava):**

```
sudo snort -dev -l .
sudo snort -r imelogfajla  
```

- snimamo saobracaj u log fajl i pregledamo (snort u sniffer mode)

**Ovde je primetno da se u nasoj mrezi odvija saobracaj između dve eksterne IP adrese (sumnjivi port je 4444) jer je poznat po koriscenju Metasploita.**

``` 
drop tcp any 4444 -> any any (msg: "blokiranje odlaznog saobraćaja na port 4444"; sid: 100001; rev:1;)
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full 
```

- dodajemo pravilo koje blokira odlazni saobracaj na sumnjivom portu i izvrsavamo

