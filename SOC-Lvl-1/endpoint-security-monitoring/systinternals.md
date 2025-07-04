# Sysinternals 

da bi smo instalirali sysinternal alate moramo imati pokrenut WebDAV  

network discovery mora biti odoboren takodje  

cilj je upoznati se sa alatima sysinternals ali ih ima previse da bi smo svaki detaljno objasnili  

# Sigcheck  

prikazuje broj verzije fajla, vremenska oznaka i detalje dig potpisa (ukljucujuci lance sertifikata), takodje moze se proveravati i na virustotal automatizovano  

`sigcheck -u -e C:\Windows\System32` provera da li postoje nepotpisane datoteke u system 32.  
- `-u` proverava datoteke pomocu virus total-a: prikazi datoteke koje virustotal ne poznaje u suprotnom prikazi samo potpisane datoteke  
- `-e` skeniraj samo izvrsene slike, bez obzira na njihovu ekstenziju  

# Streams  

alternativni tok podataka ADS je specificna za windows nfts new technology file system. Svaka datoteka ima bar jedan tok podataka $DATA  

# SDelete 

brisanje datotetka i ciscenje slobodnog prostora 

ovo su koristili napadaci i povezana je sa vise mitre tehnika  

**na dekstopu je file.txt, koristeci neki od alata pronadji koji je tekst unutar ADS**

kroz cmd odem na desktop i izvrsim komande i procitam flag  

`streams file.txt`

nakon izvrsenja dobio sam ime skrivenog fajla  

```
C:\Users\Administrator\Desktop\file.txt:
         :ads.txt:$DATA 26
		 
```

nakon toga izvrsim  

`notepad ./file.txt:ads.txt`

# TCPView  

windows program za prikaz detalja tco i udp endpoint-a  

otvaranje alata komandom iz cmd-a: `resmon`. Moze se pozvati jos sa open resurce monitor iz task manager-a  

**koriscenjem whois alata, koja je isp organizacija za udaljenu adresu**

nadjemo adresu preko domain tools  

# Autoruns  

# procdump  

# sysmon  

sistemska usluga koji prati sve dogadjaje na windowsu  

# winobj 

sesija 0 je sesija operativnog sistema a sesija 1 je sesija korisnika  

# bginfo

automatski prikazuje informacije na desktopu 

# regjump 

uzima putanju registra i otvara regedit na toj putanji  

# strings  

skenira datoteku koju mu prosledimo za pretragu unicode ascii stringova podrazumevane duzine 3 ili vise znakova  

**pokrenuti alatku strings na zoomlt.exe, koja je puna putanja do .pdb fajla**

`.\ZoomIt.exe | findstr /i .pdb`






























