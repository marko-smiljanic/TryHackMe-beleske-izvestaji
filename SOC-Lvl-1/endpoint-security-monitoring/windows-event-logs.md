# Windows event logs  

kada se desi problem na endpointu ispituju se event logovi kako bi se videli tragovi o tome sta je dovelo do problema.  

os podrazumevano zapisuje sve poruke  

tu su nam koprisni SIEM (Security Information and Event Management) alati  

u realnom scenariju ce se ispitivati logovi sa vise uredjaja  

fokus ce biti na windows-u kao najzastupljenijem os-u  

# Event viewer  

windows logovi nisu tekstualne datoteke koje se mogu otvoriti preko nekog uredjivaca teksta, medjutim sirovi podaci se mogu prevesti u xml pomocu windows api-ja.   

Ekstenzija log fajlova je .evtx i obicno se nalaze u C:\Windows\System32\winevt\Logs   

elementi event logova su:  

- system logs - povezani sa segmentima os-a, cesto su to hardverske promene, drajveri, sistemske promene itd.  
- security logs - zapis dogadjaja povezanih za logon i logoff aktivnostima, odlicni za proveru pokusaja neovlascenih aktivnosti  
- application logs - zapis dogadjaja vezaih za aplikacije instalirane na sistemu, glavne informacije su greske, dogadjaji i upozorenja  
- directory service events - promene vezane za active directory  
- file replication service event - beleze dogadje povezane sa windows serverima tokom deljenja grupnih politika i skripti za prijavljivanje sa kontrolerima domena odakle   
- dns event logs - dns serveri koriste logove da yapisu domenske dogadjaje  
- custom logs - evente evidentiraju aplikacije kojima je potrebno prilagodjeno skladistenje podataka  

tipovi event logova su: 

- error - npr. greska u ucitavanju kod startupa  
- warning - npr. disk space low
- information - npr. uspesna operacija palikacije drivera ili usluge  
- success audit - pokusaj login-a koji je uspesan  
- failure audit - neuspesan pokusaj login-a  

# Event view-er  

jedan od nacina za pristup windows logovima  

**koji je id eventa za najraniji snimljeni dogadjaj**

prvo u stablu sa desne strane otvorimo kroz foldere: application and service logs > microsoft > windows > powershell > operational i to otvorimo   

sortiramo prikaz logova po datumu i pogledmo koji je  

vm jako baguje i cak sortiranje traje 2-3 minuta  

**filtriraj dogadjaj id 4104, koja je druga komanda koja je izvrsena u powershell sesiji**

u prikazu sa desne strane u tabu actions > filter current log > i u mestu za id ukucam i pokrenem  

sortiram po datumu i kliknem na drugi po redu i pogledam koja je komanda u pitanju  

**koja je task category za event id 4104**

to vidim odmah u prikazu u glavnoj tabeli  

**analiziraj windows powershell logove, koji je task category za event id 800**

za ovo moram promeniti prikaz u glavnom stablu, idem na:  service logs > microsoft > openSSH > windows powershell i to otvorimo  

kada otvorimo dobar fajl onda pregledamo podatke bez posebih sortiranja jer treba samo task category  

# waweutils.exe 



  


 
 