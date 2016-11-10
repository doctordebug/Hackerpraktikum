#WEP

#WLAN

#RC4
(= Rivest Cipher 4)  
Stromverschlüsselung, die u.a. Für WEP genutzt wird.  
Eine Pseudozufallsfolge wird aus einer Nounce erzeugt (=Keystream). Der Plaintext wird bitweise mit XOR verknüpft um die Daten zu verschlüsseln (=Vernam).  
Die Entschlüsselung wird genauso berechnet.
  
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
