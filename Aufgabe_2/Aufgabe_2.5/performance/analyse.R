data = read.csv("C:\\Users\\olisa_000\\Uni\\Hackerpraktikum\\Hackerpraktikum\\Aufgabe_2\\Aufgabe_2.5\\klein.csv", header = TRUE)
values <- data.frame(data)
#plot(values)
barplot(values$Tupelanzahl)

d_cor <- as.matrix(cor(values$Tupelanzahl,values$Dauer.für.hacking))
plot(cor(values$Tupelanzahl,values$Dauer.für.hacking))
bp<-barplot(table(values$Tupelanzahl,values$Dauer.für.hacking))

car_data = data.frame(values$Tupelanzahl,values$Dauer.für.hacking,values$Modell.)
print(car_data)
plot(car_data)
boxplot(car_data$values.Dauer.für.hacking)

#untersuchte TUpel:
print(length(car_data$values.Tupelanzahl))
#erfolgreich key berechnet:
erfolgreich2 = subset(car_data,  car_data$values.Modell. == "True")
print(length(erfolgreich2$values.Tupelanzahl))

#anzahl erfolgreicher berechnungen
erfolgreich2 = subset(erfolgreich2,  erfolgreich2$values.Tupelanzahl < 90000)
erfolgreich2$cat_class<-cut(erfolgreich2$values.Tupelanzahl, c(20000,30000,40000,50000,60000,70000,80000))  
bp<-barplot(table(erfolgreich2$cat_class), main="Angriff nach Klein: Erfolgreiche Tests für WEP40", xlab="Untersuchte Tupelanzahl", ylab="Anzahl Erfolgsreicher Angriffe", axisnames=F, ylim=c(0,1000))
axis(1,at=bp, labels = c("30000","40000","50000","60000","70000","80000"))

myFun <- function(x) {
  c(min = min(x), max = max(x), 
    mean = mean(x), median = median(x), 
    std = sd(x))
}
print(tapply(erfolgreich2$values.Dauer.für.hacking, erfolgreich2$values.Tupelanzahl, myFun))

########################################################################################################################################################################################################

data = read.csv("C:\\Users\\olisa_000\\Uni\\Hackerpraktikum\\Hackerpraktikum\\Aufgabe_2\\Aufgabe_2.5\\benchmakring_60_refactored.csv", header = TRUE)
values <- data.frame(data)
barplot(Values$Tupel)

plot(cor(values$Tupel,values$dauer.Gesamt))
bp<-barplot(table(values$Tupel,values$dauer.Gesamt))

car_data = data.frame(values$Tupel,values$dauer.Gesamt,values$Success)
print(car_data)
plot(car_data)
boxplot(car_data$values.dauer.Gesamt)

print(length(car_data$values.dauer.Gesamt))
erfolgreich = subset(car_data,  car_data$values.Success == "FALSCH")
print(length(erfolgreich$values.Tupel))


#anzahl erfolgreicher berechnungen
erfolgreich = subset(erfolgreich,  erfolgreich$values.Tupel < 90000)
erfolgreich$cat_class<-cut(erfolgreich$values.Tupel, c(20000,30000,40000,50000,60000,70000,80000))  
bp<-barplot(table(erfolgreich$cat_class), main="Optimierter Angriff nach Klein: Erfolgreiche Tests für WEP104", xlab="Untersuchte Tupelanzahl", ylab="Anzahl Erfolgsreicher Angriffe", axisnames=F, ylim=c(0,600))
axis(1,at=bp, labels = c("30000","40000","50000","60000","70000","80000"))

myFun <- function(x) {
  c(min = min(x), max = max(x), 
    mean = mean(x), median = median(x), 
    std = sd(x))
}



# Create Line Chart

# convert factor to numeric for convenience 

erfolgreich2 = subset(erfolgreich2,  erfolgreich2$values.Tupelanzahl > 21000)
line_1 = aggregate(erfolgreich$values.dauer.Gesamt, by=list(Category=erfolgreich$values.Tupel), FUN=mean)
line_2 = aggregate(erfolgreich2$values.Dauer.für.hacking, by=list(Category=erfolgreich2$values.Tupelanzahl), FUN=mean)
line_1 <- subset(line_1, line_1$Category > 23000)

plot(line_2)
lines(line_1, type="o", pch=22, lty=2, col="blue")
lines(line_2, type="o", pch=22, lty=2, col="red")

plot(line_1,type = "o",col = "red", xlab = "Month", ylab = "Rain fall", main = "Rain fall chart")
lines(line_2, type = "o", col = "blue")

line_1$x1 = line_2$x
print( line_1 )
plot(line_1)


title(main="Zeitvergleich", font.main=4)




library("reshape2")
library("ggplot2")

ggplot(line_1, aes(x=line_1$Category)) + xlab("Anzahl Tupel") +  ylab("Zeit in ms") +  geom_line(aes( y=line_1$x1),size=1.2,colour="blue") +geom_line(aes( y=line_1$x),size=1.2,colour="red") + ggtitle("Zeitvergleich der Angriffe") + scale_color_manual(labels = c("T999", "T888"), values = c("blue", "red")) +theme_bw() + guides(color=guide_legend("my title")) 
