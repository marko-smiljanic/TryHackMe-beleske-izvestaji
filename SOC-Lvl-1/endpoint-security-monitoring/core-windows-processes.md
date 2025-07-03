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





















