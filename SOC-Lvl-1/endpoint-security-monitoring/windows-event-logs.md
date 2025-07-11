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

- `XPath Query: *[System[(Level <= 3) and TimeCreated[timediff(@SystemTime) <= 86400000]]]` bira sve dogadjaje iz kanala ili event dnevnika gde je nivo ozbiljnosti manji ili jednak 3 i dogadjaj se desio u poslednja 24h  

https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events#xpath-10-limitations  

primer raznih upita:  

- `Get-WinEvent -LogName Application -FilterXPath '*/System/'`
- `Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=100'` id dogadjaja je 100  
- `wevtutil.exe qe Application /q:*/System[EventID=100] /f:text /c:1` 
- `Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"]'` 
- `Get-WinEvent -LogName Application -FilterXPath '*/System/EventID=101 and */System/Provider[@Name="WLMS"]'`

event data ne sadrzi uvek informacije  

gledamo xml prikaz dogadjaja za pravljenje upita  

- `Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="System"' -MaxEvents 1`

**koristeci znanje get win event i xpath koji je query da se nadje wlms event sa System Time of 2020-12-15T01:09:08.940277500Z**

`Get-WinEvent -LogName Application -FilterXPath "*[System/Provider[@Name='WLMS'] and System/TimeCreated[@SystemTime='2020-12-15T01:09:08.940277500Z']]"`

mora da se formatira pravilno, nece da prizna odgovoro, jer sto ne bi smo gubili malo vreme na gluposti  

`Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"] and */System/TimeCreated[@SystemTime="2020-12-15T01:09:08.940277500Z"]'`  

**koristiti get winevent i xpath, koji je query koji trazi usera koji se zove Sam sa Logon Event ID 4720**

`Get-WinEvent -LogName Security -FilterXPath "*[EventData/Data[@Name='TargetUserName']='Sam' and System/EventID=4720]"`

opet format: `Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="Sam" and */System/EventID=4720'`

**koliko rezultata je vratio prethodni query**

izvrsi se i vidi se 2 kom 

**koja je poruka koja se vidi kada se izvrsi prethodni upit**

A user account was created

**opet prethodni upit sa Sam korisnikom, u koje vreme je zabelezen doagadjaj sa id 4724 (MM/DD/YYYY H:MM:SS [AM/PM])**

takvog id-ja nema, ima samo 4720 2 komada, ne znam da li ja nisam dobio resenje ili je greska na TryHackMe platformi, ali svakako je naporno  

**u rezultatu pretohnodg upuita, koji je provider name**

izvrsim i vidim odmah  

# Event IDs  

id-evi se mogu naci na razlicitm sajtovima    

mitre attack: svaki moze sadrzati odeljak sa savetima za ublazavanje tehnike i savetima za otkrivanje    

mora se omoguciti funkcija: Local Computer Policy > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell   

omoguciti: Local Computer Policy > Computer Configuration > Administrative Templates > System > Audit Process Creation, ovo ce generisati dogadjaj sa id-em 4688 

# Zadaci  

sledeci zadaci se zasnivaju na fajlu na desktopu  

koristiti bilo koji od alata da se odgovori na pitanja u nastavku  

scenario 1 (pitanje 1 i 2): administratori servera su ulozili brojne zalbe menadzmentu u vezi sa blokiranje powershell-a u okruzenju, menadzment je konacno odobrio upotrebu powershella u okruzenju. Sada je potrebna vidljivost kako bi se osiguralo da nema praznina u pokrivenosti. 

> Istražili ste ovu temu: koje logove pregledati, koje ID-ove događaja pratiti itd. Omogućili ste PowerShell zapisivanje na testnoj mašini i zamolili kolegu da izvrši različite naredbe.  

scenario 2 (pitanje 3 i 4): tim za bezbednost vise koristi event logove. Zele da osiguraju da mogu da prate da li se evidencija dogadjaja brise. Dodelili ste kolegi da izvrsi ovu radnju  

scenario 3 (pitanja 5, 6, 7): tim za pretnje je podelio svoje istrazivanje o emotetu. Savetovali su da se potrazi id dogadjaja 4104 i tekst "ScriptBlockText" unutar elementa event data. Pronadjite kodirani powershell korisni payload  

scenario 4 (pitanja 8 i 9): stigla je prijava da je pripravnica osumnjicena da je pokrenula neobicne komande na svojoj masini, kao sto je nabrajanje clanova grupe administratora. Visi analiticar je predlozio pretragu C:\Windows\System32\net1.exe. Potvrdite sumnju.  

**1. Koji je id za detektovanje powershell downgrade attack?**

istrazujemo na netu ovo, google search zbog AI izbacuje odmah rezultat  

nasao sam i na mitre sajtu za downgrade attack u pretrazi sam kucao windows event i nasao id  

**2. Koji je date and time kad se ovaj napad dogodio MM/DD/YYYY H:MM:SS [AM/PM]** 

da bi smo ovo nasli moramo primeniti filter za event id koji je 400 (iz prethodnog zadatka)   

kada otvorim event viewer idem na filter current log > i ukucam trazeni id  

kada sam ovo filtrirao onda samo uzmem prvi iz rezultata, nije se u zadatku trazilo da se vidi koji je najraniji ili najkasniji i sva sreca iz rezultata prvi uzmem samo  

da mi ovo nije uspelo iz prve morao bih svaki event da istrazim da vidim koji se razlikuje  

**3. Log clear event je zabelezen, koji je event record id**

hint: proveri xml view  

prvo izguglamo log clear event id koji je: 1102 i 104  

onda pretrazimo na isti nacin kao u prethodnom zadatku, u polje za id mozemo da unesemo oba id-ja od jednom: filter current log > i ukucam ovako: 1102, 104  

kao rezultat dobijemo jedan dogadjaj, i poklopilo se sa id-em 104  

u donjem porozoru ispod rezultata idem na details pa na xml view i tamo trazim resenje pod tagom event record id  









 
 