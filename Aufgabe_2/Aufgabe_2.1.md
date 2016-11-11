#WEP
[WEP](https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy)
#WLAN
[WLAN/IEEE 802.11](https://de.wikipedia.org/wiki/IEEE_802.11)
#RC4 *
(= Rivest Cipher 4)  
Stromverschlüsselung, die u.a. Für WEP genutzt wird.  
Eine Pseudozufallsfolge wird aus einer Nounce erzeugt (=Keystream). Der Plaintext wird bitweise mit XOR verknüpft um die Daten zu verschlüsseln (=Vernam).  
Zum Entschlüsseln verwendet man den gleichen Algorithmus, wobei der Schlüsseltext anstelle des Klartextes eingegeben wird. Zwei XOR-Verknüpfungen mit derselben Zufallszahl heben sich gegenseitig auf, und als Ausgabe entsteht wieder der Klartext.
  
Um den Schlüsselstrom zu generieren, benutzt die Chiffre einen S-Box und zwei Pointer (Hier: i und j).

##Algorithmus zur Initialisierung der S-Box:  

```
  k[]: gegebene Schlüssel-Zeichenfolge der Länge 5 bis 256 Byte
  L := Länge des Schlüssels in Byte
  s[]: Byte-Vektor der Länge 256
  Für i = 0 bis 255
    s[i] := i
  j := 0
  Für i = 0 bis 255
    j := (j + s[i] + k[i mod L]) mod 256
    vertausche s[i] mit s[j]
```

##Algorithmus zur Berechnung der Zufallsfolge:

```
  klar[]: gegebene Klartext-Zeichenfolge der Länge X
  schl[]: Vektor zum Abspeichern des Schlüsseltextes
  i := 0
  j := 0
  Für n = 0 bis X-1
    i := (i + 1) mod 256
    j := (j + s[i]) mod 256
    vertausche s[i] mit s[j]
    zufallszahl := s[(s[i] + s[j]) mod 256]
    schl[n] := zufallszahl XOR klar[n]
```

##Sicherheit

Wie jede Stromchiffre bietet auch RC4 keinen Integritätsschutz. Wenn ein Angreifer ein Bit einer verschlüsselten Nachricht ändert, so ändert er damit auch das gleiche Bit des Klartextes.


[*] https://en.wikipedia.org/wiki/RC4

#Paper
## 1. Attacks on the RC4 stream cipher [Andreas Klein]
### Kapitel 1: Einführung
### Kapitel 2: RC4-Algorithmus
#### 2.1: Beschreibung
s.o.
#### 2.2: Korrelationen im RC4-Pseudozufallsgenerator
Die von RC4 erzeugte Pseudosufallssequenz (=PZS) unterscheidet sich in einigen Punkten von einer "richtigen" Zufallsfolge. Die Summe der letzten Bits in Schrit t und t+2 korreliert gegen 1. J.Dj. Golic kam zu dem Schluss, dass 2^40 Bytes von der RC4-PZS unterscheidbar sind zu einer richtigen Zufallssequenz.  
Weitere Untersuchungen von S.R. Fluhrer und D.A. McGrew haben beweisen, das die gemeinsame WK von zwei aufeinander folgenden Bytes sich signifikant von einer Zufallsfolge unterscheiden.  
#### 2.3 Schwachstelle der Key-Scheduling-Phase
Im Idealfall besteht ein Schlüssel aus n unabhägig, identischen und gleichverteilten Elementen aus Z/nZ und gerneriert n^n gleichwahrscheinliche Schlüssel.
Jedoch ist n! kein Teiler von n^n. Daher muss sich die Verteilung der initialen Permutation von einer Gleichverteilung unterscheiden.
(=> Siehe Studie von I.Mironov.)  
Eine weitere, frühbekannte Schwachstelle ist, dass das erste Byte der PZS nicht wirklich zufällig ist. Angriff von S. Fluhrer, I.martin und A. Shamir nimmt an, dass der Initialisierungsvektor vor dem Hauptschlüssel steht und die ersten zwei Bytes die Form (b,n-1) haben, wobei b das Byte des Hauptschlüssel ist, welches rekontruiert werden soll. Wenn ein Angreifer kei neChance hat den Initialisierungsverktor zu beeinflussen, muss er warten, bis der initialiserungsverktor die gewünschte Form annimmt. Die ist in druchschnittlich einre aus n^2 Situngen der Fall. **Die Authoren zeigen, dass dieser Angriff auf WEP angewendet warden kann.**
### Kapitel 3: Eine Korrelation im RC4 Pseudo-Zufalls-Generator
Es wird festgestellt, dass eine starke Korrelation zwischen den beobachtbaren/abfangbaren Werten i, S[k] und den internen Werten von j, S[j] und S[i] besteht. In der Zusammenfassung: Ohne Beweis.  
Genaue Formel steht auf Seite 5 Unten. (bitte noch einpflegen)  
### Kapitel 4: Angriff auf die erste Runde
Annahme: Sesseion_keys habe ndie Form: *main key || Initialisierungsvektor*  
Der Angriff bestimmt die Summe der ersten 2 Bytes des Schlüssels. Später wird auch ein Angriff gezeigt, bei welchem der Initialisierungsvektor an erster Stelle steht.
#### 4.1 Die Basisversion des Angriffes
Wir betrachten die Permutation im Key-Scheduling:  
```
  // S = [0,1,2.....n-1]
  j := 0
  For i = 0 to n - 1
    j := (j + s[i] + k[i mod L]) mod 256
    swap s[i] mit s[j]
```
Hier sideht man leicht, nach dem ersten Schritt gilt:  
```
j = 0+0+K[0] = K[0]  
==> S[0] <-> S[K[0]]  
```  
  
So lässt sich die zweite Runde (mit WK 1 - 1/n) ebenfalls rekontruieren: 
```  
j = K[0] + 1 + K[1]  
==> S[1] <-> S[ K[0] + 1 + K[1] ]  
  
K[0] + 1 + K[1] wird im Weiteren t genannt.
```
  
4 Spezialfälle betrachten (werde ich ergänzen, wenn diese sich im weiteren Paper als wichtig herrausstellen)  
  
Zusammengefasst kann man sagen, dass für fixes K[0] kann der Wert t von S[1] aus K[1] berechnet werden.
**Achtung:** Wird der Wert S[1] beim ersten Mal überschreiben, (j = 1) funktioniert dies nicht. Die WK, das die nach 2 Runden passiert liegt bei:  
`(1- (1/n))^(n-2)` das ist ungefähr gleich `1/e` mit n = Schlüssellänge, e = Eulerische Zahl.
Nun wissen wir Folgendes:
Wir wissen, dass der Wert von S[1] zu Beginn des RC4-PZG t ist. Wobei T mit hoher WK (1/e) nur von K[0] und K[1] abhängt.
Nun kann die Korrelation aus *Kapitel 3* benutzt werden um t aus der beobachteten RC4-PZS zu erhalten.
Dazu schauen wir uns die Generierung des ersten Pseudozufall-Bytes (PZB) an.
Zuerst wird i auf 1 gesetzt. So werden S[1] und S[j] getauscht. Nun enthält S[j] den interessanten Wert t. Nach Kapitel 3 wissen wir: `S[j] = 1 - S[k] mod n` mit Wahrscheinlichkeit: `2/n`  Alles zusammen haben wir nun:
`R( t = 1 - S[k] mod n) = [...] 1.36 /n`


**Unser Angriff hat nun folgende Form:**
Für verschiedene Initialisierungsverktoren (n-Stück) können wir die ersten Bytes 'x_i' mit `1 <= i <= n`beobachten und `t_i = 1 - x_i` ausrechnen. Wie Wk, das t_i den richtigen Wert annimmt liegt bei `1.36/n` alle anderen Werte haben eine WK von unter `1/n` Wenn die Anzah lder Session großgenug ist, kann man den Wert mit hoher WK bestimmen.
