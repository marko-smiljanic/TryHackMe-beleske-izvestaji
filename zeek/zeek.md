# Zeek, upotreba i vezbanje  

Zeek je alat koji se koristi za nadzor mreze

`zeek -C -r sample.pcap`  

- citanje pcap fajla pomocu zeek-a  

kada ovo uradimo dobicemo neke log fajlove i citanje tih log fajlova mozemo raditi za komandom `cat`  

kada sa `cat` otvorimo neki log fajl onda cemo moci da vidimo sve sto se nalazi u njemu  

posto je to gomila podataka, na pocetku sadrzi spisak polja na osnovu kojih su grupisani  

`zeek-cat` je komanda pomocu koje izdvajamo odredjene stvari iz log-a (ugradjeno u zeek alat)  

`zeek -C -r sample.pcap`  

- citamo pcap fajl

`cat dhcp.log`

- citanje odabranog log fajla



