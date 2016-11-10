#WEP

#WLAN

#RC4
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
