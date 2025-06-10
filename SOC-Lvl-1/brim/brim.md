# Brim - beleske i vezbanje

primarna funkcija je obradjivanje pcap datoteka i datoteka logova - pregled i analitika  

koristi zeek format za obradu logova i podrzava zeek potpise i suricata pravila za detekciju  

Brim smanjuje vreme i trud koji su potrebni za obradu velikih (preko 1gb) pcap fajlova (zeek je za velike pcap fajlove jos bolji ali je CLi aplikacija)

Brim je GUI aplikacija. Nesto kao zeek ali gui.  

Brim radi i sa query-jima. Pomocu upita dobavljammo razne stvari iz pcap fajlova.   

Brim query izrazi su slicni kao zeek-ovi. Isto se pristupa field-ovima u fajlovima ali se prvo pise `_path=="http"` kako bi znali koji fajl gledamo. Query se pise u polje za pretragu  








