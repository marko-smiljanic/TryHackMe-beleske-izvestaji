# Sysmon  

slican je windows event logs-u samo sto ima vise detalja i dodatne kontrole  

kada se jednom instalira ostaje prisutan kakon ponovnog pokretanja sistema i evidentira aktivnosti u windows event log  

najcesce se koristi u kombinaciji sa SIEM alatima  

dogadjaji unutar sysmona se cuvaju na: Applications and Services Logs/Microsoft/Windows/Sysmon/Operational  

potrebna mu je konfiguraciona datoteka da bi mogao da analizira binarne datoteke kao dogadjaje koje prima  

primetno je da vecina pravila u sysmon -config iskljucuje dogadjaje imesto da ih ukljucuje, to je neki njihov nacin filtriranja da bi se smanjio broj dogadjaja  

## event id 1: kreiranje procesa  

trazi sve procese koji su kreirani, mozemo ga koristiti za trazenje poznatih sumnjivih procesa ili procesa sa greskama u kucanju kako bi se smatrali anomalijom  

```
<RuleGroup name="" groupRelation="or">
	<ProcessCreate onmatch="exclude">
	 	<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
	</ProcessCreate>
</RuleGroup>
```

odredjuje id dogadjaj iz kog treba izvuci podatke kao i uslov koji treba traziti (u ovom slucaju iskljucuje proces svhost.exe iz evidencije dogadjaja)  

## event id 3: networck connection   

dogadjaj iz mrezne veze ce traziti dogadjaje koji se izvrsavaju na daljinu, ovo ce ukljucivati izvore sumnjivih binarnih datoteka i otvorene portove  

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
	 	<Image condition="image">nmap.exe</Image>
	 	<DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
	</NetworkConnect>
</RuleGroup>
```

u ovom slucaju trazimo nmap.exe, drugi metod identifikuje port 4444 koji se obicno koristi sa metasploitom  

ako se uslov ispuni kreirace se event i pokrenuce upozorenje za soc  

## event id 7: image loaded  

trazi sve dll datoteke koji su ucitani prcesi, ovo izaziva veliko opterecenje sistema  

```
<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
	 	<ImageLoaded condition="contains">\Temp\</ImageLoaded>
	</ImageLoad>
</RuleGroup>
```

trazi dll ucitane u folderu temp  

## event id 8: create remote thread  

prati procese koji ubrizgavaju kod u druge procese  

```
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="include">
	 	<StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
	 	<SourceImage condition="contains">\</SourceImage>
	</CreateRemoteThread>
</RuleGroup>
```

prva metoda ce traziti memorijsku adresu za odredjeni uslov zavrsetka koji bi mogao biti indikator cobalt strike signala, a druga ce traziti ubrizgane procese koji nemaju roditeljske procese  

## event id 11: file created  

moze se koristiti za identifikaciju imena i potpisa kreiranih fajlova  

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
	 	<TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
	</FileCreate>
</RuleGroup>
```

primer monitora rasomware-a  

## event id 12,13,14: registry event  

ovaj dogadjaj trazi izmene ili modifikacije registra, mogu ukljucivati zloupotrebu kredencijala  

```
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
	 	<TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
	</RegistryEvent>
</RuleGroup>
```







