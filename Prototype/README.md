Hva gjør prototypen vi har lagd?
Repoen inneholder nå en tidlig prototype som vi har tenkt å bruke til bachelorprosjektet vårt for SmartSecLab. Målet her er:
1. Hente CVE-data fra NVD - 2. Finner en direkte github lenke i refereansene - 3. Henter ut patch/diff for committen i github - 4. Dermed lagres patch og metadata på en strukturert og ryddig måte i SQLite- databasen.

Prototypen er ikke et ferdig produkt, men en løsning som viser tankgegangen vår og retningen vi tenker å løse prosjektet på. En såkalt Proof of concept.

Innholdet i prototypen: 


Hvordan kjører man den?
lager .env med tomme keys
kommandoen "pip install -r requirements.txt"
"python main.py"

