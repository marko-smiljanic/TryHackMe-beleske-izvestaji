# NetworkMiner  beleske i vezbe

ima gui. Sluzi za dubinsku forenzicku analizu mreznih podataka, uglavnom posle dogadjaja  

-dva osnovna moda rada: pasivno prikupljanje i analiza mreznih paketa i live capture 
-ne blokira sobracaj, ne detektuje napede (samo pomaze u analizi i rekonstrukciji incidenata)  
-moze da otkrije operativni sistem napadaca, analizira protokole, vadi citave fajlove i kredencijale 

network miner se moze koristiti i za napad (kradja kredencijala). Za dublje analize se koristi wireshark  
ogranicen je u analizi i filterisanju  

dakle: Network Miner radi pasivnu detekciju - ne prati saobraćaj u realnom vremenu sa ciljem da zaustavi napad, već prikuplja i analizira podatke koje vidi, pomažući da se otkriju tragovi napada ili sumnjive aktivnosti kasnije, kroz forenzičku analizu.

### postoje razlike u verzijama programa:  
- starije verzije (1.6) mogu da daju informacije o frame-ovima, vise detalja u nekim stvarima,
- dok novije verzije (2.7) mogu da pokazu duplirane mac adrese  

nemam zadataka koje bih izdvojio, meni ovo izgeda slicno kao snort u pcap rezimu samo graficki prikazano i malo drugacije stavke u prikazu  




