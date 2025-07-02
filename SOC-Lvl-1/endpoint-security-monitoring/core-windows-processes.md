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

























