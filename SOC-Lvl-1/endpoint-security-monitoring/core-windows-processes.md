# Core Windows Processes

ovde cemo govovoriti o normalnim procesima u windows os i kako da ih razlikujemo od losih procesa   

nekad EDR alati mogu da pogrese i zbog toga je vazno da mozemo da razlikujemo normalni od sumnjivog binarnog fajla  

# Task Manager, pocess hacker, process explorer  

ugradjeni alat u windows. Koristio sam ga mnogo puta.  

pruza informacije o koriscenju hardvera i resursa i moze da se koristi za ubijanje procesa  

task manager nema informacije o maticnom procesu  

najbolje je da postavimo kolone PID i path procesa  

nemamo prikaz procesa parent > child  

proces haler ima child > parent  

# System  

PID broj je procesima dodeljen random, ali to nije slucaj i za sistmske proces jer je on uvek 4  

informacije o ovom procesu mogu biti drugacije u zavisnosti koji se proces tracker koristi    

neobicno ponasanje za system proces:  

- roditeljski proces, pored system idle proces   
- vise instanci sistema (uvek mora biti samo jedna instanca)   
- drugaciji PID broj (uvek mora biti 4 za system proces) 
- nepokretanje iz sesije 0  

# System > smss.exe 

session manager subsystem (windows session manager), odgovoran je za kreiranje novih sesija. Prvi proces korisicnog rezima koji pokrece jezgro  

sta je sumnjivo:  

- drugaciji roditeljski proces osim system (4)
- putanja slike nije na c/windows/system32  
- vise od jednog procesa koji se pokrece (child se sami zavrsavaju i izlaze nakon nove sesije)  
- korisnik koji radi nije korisnik sistema  
- neocekivani unosi u registar za podsistem  

# csrss.exe  

client server runtime process  

ovaj proces je kljucan za rad sistema  

sta je neobicno ponasanje:  

- pravi parent proces (smss.exe poziva ovaj proces i samostalno se izvrsava)  
- putanja datoteke slike koja nije c/windows/system32  
- suptilne pravopisne greske za skrivanje laznih procesa maskiranih kao csrss.exe  
- korisnik nije koristik sistema   

# wininit.exe  

services.exe - service control manager
Isass.exe - moramo ukljuciti credential and key guard i samo tada cemo videti ovaj proces, local security authority  

sta nije normalno:  

- pravi roditeljski proces (smss.exe poziva ovaj proces i samostalno se izvrsava)  
- putanja datoteke slike koja nije c/windows/system32  
- suptilne pravopisne greske radi skrivanja laznih procesa  
- vise pokrenutih instanci  
- ne radi kao sistem  

# wininit.exe > services.exe  

sluzi za rukovanje sistemskim servisima, odrzava bazu podataka kojoj se moze postavljati upit pomocu ugradjenog sc.exe  

informacije o procesu se cuvaju u HKLM\System\CurrentControlSet\Services.  

ovaj proces je roditelj nekoliko drugih kljucnih procesa  

sta je neobicno:  

- roditeljski proces koji nije wininit.exe  
- putanja slike koja nije c/windows/system32  
- suptilne pravopisne greske zbog skrivanja laznih procesa  
- vise pokrenutih instanci  
- ne radi kao sistem  

# wininit.exe > services.exe > svchost.exe  

odgovoran je za hostovanje i upravljanje windows servisima  

servisi koji se pokrecu u ovom procesu su implementirani kao dll-ovi.  

dll-ovi se cuvaju pod parameters potkljucem u serviceDLL, puna putanja je HKLM\SYSTEM\CurrentControlSet\Services\SERVICE NAME\Parameters   

u proces hacker desni klik na proces svchost.exe > services > dcom launch > go to service  

ovaj proces ima mnogo instanci na bilo kom sistemu i zbog toga je meta napadaca jer pokusavaju zlonamerni softver da sakriju i da ga napisu sa scvhost.exe  


sta je neobicno:  

- parent koji nije services.exe  
- putanja datoteke koja nije c/windows/system32 
- pravopisne greske  
- odsustvo parametra -k (sluzi za grupisanje slicnih servisa zbog deljenja istog procesa, zbog potrosnje resursa)   

# lsass.exe  

roditelj wininit.exe  

odgovoran za sprovodjenje windows bezbednosne politike  

proverava korisnike koji se prijavljuju na windows server ili racunar i obradjuje promene lozinki i kreira pristupne tokene  

paketi za autentifikaciju: HKLM\System\CurrentControlSet\Control\Lsa  

uobicajni alati kao sto je mimikatz koriste se za otkrivanje kredencijala ili zlonamerni programi koji imitiraju ovaj proces kako bi se sakrili  

sakrivaju se tako sto imenuju zlonamerni softver po ovom procesu ili malo pogresno napisu  

uvek je jedna instanca  

sta je neobicno:  

- nadredjeni proces koji nije wininit.exe  
- putanja datoteke koja nije c/windows/system32  
- pravopisne greske  
- ne radi kao sistem  

# winlogon.exe  

sluzi za rukovanje sekvencom bezbedne paznje (alt + ctrl + delete kada korisnici stistkaju da bi uneli svoje kor ime i lozinku)  

ovaj proces je odgovoran za ucitavanje korisnickog profila  

sumnjivo:  

- smss.exe poziva ovaj proces i samostalno se izvrsava, nema roditeljski proces    
- putanja datoteke koja nije c/windows/system32  
- pravopisne greske  
- ne radi kao sistem 
- vrednost u shell-u osim explorer.exe  

# explorer.exe  

windows explorer, omogucaba funkcionalnost za druge funkcije kao sto su meni start i taskbar  

winlogon pokrece userinit exe nakon cega se userinit.exe zatvara i zbog toga roditeljski proces ne postoji  

sumnjivo:  

- userinit.exe poziva ovaj proces i zavrsava se, dakle nema roditeljskog procesa  
- putanja datoteke koja nije c/windows/system32  
- pravopisne greske  
- pokretanje kao nepoznati korisnik  
- odlazne tcp/ip veze  


sa uvodjenjem windows 10 ovi procesi su dodati na listu osnovnih procesa  

ako je credential guard omogucen na endpointu pokrenuce doodatni proces koji ce biti podproces za wininit.exe a taj proces je lsaiso.exe  

ostali procesi su runtimebroker.exe, takhostw.exe  

 









