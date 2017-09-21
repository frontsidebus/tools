# Linux and Windows Scripts and One-liners
# 
Anything overtly dangerous, I have tried to comment as such. Most of the other things included here are read only commands or scripts that could be useful depending on the situation 


#Stingray VTM Log TLS Version (TS)
#Example script, that sends the string to log.info:
#Get the encryption cipher
```
$cipher = ssl.clientCipher(); 
log.info( "Encrypted with ".$cipher );
```
