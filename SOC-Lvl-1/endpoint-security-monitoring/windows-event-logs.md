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

# Event viewer  

jedan od nacina za pristup windows logovima  







  


 
 