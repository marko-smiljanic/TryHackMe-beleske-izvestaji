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

# wevtutil.exe 

tesko je pregledati logove rucno. Logovi se mogu pregledati i pisanjem skripti  

u powershellu koristimo komandu `wevtutil.exe /?` da pregledamo mogucnosti i informacije alata  

ako npr hocemo da koristimo komandu `qe` koristimo isti nacin za dobavljanje informacija o njenom koriscenju: `wevtutil qe /?`  

**koliko je log name u masini?**

hint: koristimo el komandu    

prvo kucam informacije da vidim kako se koristi komanda `wevtutil el /?`

onda kucam `wevtutil el | Measure-Object` i dobijem resenje  

**koji event fajlovi ce biti procitani kada se koristi query-event komanda**

resenje ovog zadatka je teorijsko, znaci treba ukucati `wevtutil qe /?` i videti prvu recenicu ispod o informacijama koje fajlove cita  

**koja opcija bi se koristila kao putanja za logfile**

primenimo istu komandu i nakeako zakljucimo ovu nelogicnost koju pita, jer nije bas ocigledan odgovor iz teksta  

**koja je vrednost za /q**

primenimo istu komandu i trazimo q i nadjemo sta je value    

**HINT: sledeci zadatak je baziran na komdani:**`wevtutil qe Application /c:3 /rd:true /f:text`

**koji je logname**

primenimo komandu i jednostavno procitamo  

**sa je /rd opcija**

ovde koristimo komdnau `wevtutil qe /?` i pronadjemo opciju i vidimo za sta je  

**za sta je /c**

isto kao prosli z, ista komanda samo trazimo drugu stavku    

# get-winEvent  

preuzima logove i datoteke na lokalnim i udaljenim racnunarima  

> **NAPOMENA:** komanda `GetWinEvent` je zamenjena sa `Get-EventLog`

- `Get-WinEvent -ListLog *` dobavljanje lokalno svih dnevnika dogadjaja  
- `Get-WinEvent -ListProvider *` preuzimanje dobaljvaca log dnevnika i eventa  
- `Get-WinEvent -LogName Application | Where-Object { $_.ProviderName -Match 'WLMS' }` filtriranje logova  
- komanda za filtriranje  
```
Get-WinEvent -FilterHashtable @{
  LogName='Application' 
  ProviderName='WLMS' 
}
   
```
- `@{ <name> = <value>; [<name> = <value> ] ...}` sintaksa hes tabele  
- `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString'`  

**za odgovore na sledeca pitanja po potrebi koristiti online dokumentaciju: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5&viewFallbackFrom=powershell-7.1**

**izvrsite komandu iz prvog primera, koja su imena loga povezana sa openSSH***  

izvrsimo komandu i pogledamo

kad ovo izvrsimo dobicemo gomilu teksta ali resenje je pri dnu    

`Get-WinEvent -ListLog *`

**izvrsiti 8. komandu i umesto policy pretraziti za powershel, koje je ime 3. log providera**

izvrsimo i kopiramo pod name listu  

`Get-WinEvent -ListProvider *PowerShell*`

**izvrsiti komandu 9, koristiti Microsoft-Windows-PowerShell  kao log providera, koliko event id je prikazano za ovog event providera**

izvrsimo komandu i dobijemo broj    

`(Get-WinEvent -ListProvider Microsoft-Windows-PowerShell).Events | Format-Table Id, Description | Measure-Object`

**kako specificiramo broj eventa za prikaz**

resenje je: `-MaxEvents`  

**kada se koristi parametar FilterHashtable i filtrira po noviu koja je vrednost za Informational**

proveriti online dokumentaciju za ovo  

# Xpath queries   

sluzi za adresiranje delova xml dokumenata i manipulisanje stringovima  





















 
 