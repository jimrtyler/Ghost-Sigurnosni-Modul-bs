# 👻 Ghost Sigurnosni Modul
**PowerShell-baziran Windows i Azure sigurnosno učvršćavanje alat**

> **Proaktivno sigurnosno učvršćavanje za Windows krajnje tačke i Azure okruženja.** Ghost pruža PowerShell-bazirane funkcije učvršćavanja koje mogu pomoći u smanjenju uobičajenih vektora napada onemogućavanjem nepotrebnih servisa i protokola.

## ⚠️ Važne Odricanja

**TESTIRANJE JE POTREBNO**: Uvijek testirajte Ghost u ne-produkcijskim okruženjima prvo. Onemogućavanje servisa može utjecati na legitimne poslovne funkcije.

**NEMA GARANCIJA**: Iako Ghost cilja na uobičajene vektore napada, nijedan sigurnosni alat ne može spriječiti sve napade. Ovo je jedna komponenta sveobuhvatne sigurnosne strategije.

**OPERACIJSKI UTJECAJ**: Neke funkcije mogu utjecati na funkcionalnost sistema. Pažljivo pregledajte svaku postavku prije implementacije.

**PROFESIONALNA PROCJENA**: Za produkcijska okruženja, konsultujte se sa sigurnosnim stručnjacima da osigurate da postavke odgovaraju potrebama vaše organizacije.

## 📊 Sigurnosni Pejzaž

Štete od ransomware-a dostigle su **57 milijardi dolara u 2025.**, a istraživanja pokazuju da mnogi uspješni napadi eksploatišu osnovne Windows servise i pogrešne konfiguracije. Uobičajeni vektori napada uključuju:

- **90% ransomware incidenata** uključuje eksploataciju RDP-a
- **SMBv1 ranjivosti** omogućile su napade poput WannaCry i NotPetya
- **Makroi dokumenata** ostaju primarni metod dostavljanja malware-a
- **USB-bazirani napadi** nastavljaju ciljati vazduhom izolovane mreže
- **Zloupotreba PowerShell-a** značajno se povećala u posljednjim godinama

## 🛡️ Ghost Sigurnosne Funkcije

Ghost pruža **16 Windows funkcija učvršćavanja** plus **Azure sigurnosnu integraciju**:

### Windows Učvršćavanje Krajnjih Tačaka

| Funkcija | Svrha | Razmatranja |
|----------|-------|-------------|
| `Set-RDP` | Upravlja pristupom udaljenom radnom stolu | Može utjecati na udaljenu administraciju |
| `Set-SMBv1` | Kontroliše legacy SMB protokol | Potreban za vrlo stare sisteme |
| `Set-AutoRun` | Kontroliše AutoPlay/AutoRun | Može utjecati na udobnost korisnika |
| `Set-USBStorage` | Ograničava USB uređaje za skladištenje | Može utjecati na legitimnu USB upotrebu |
| `Set-Macros` | Kontroliše izvršavanje Office makroa | Može utjecati na dokumente s omogućenim makroima |
| `Set-PSRemoting` | Upravlja PowerShell udaljenim pristupom | Može utjecati na udaljeno upravljanje |
| `Set-WinRM` | Kontroliše Windows Remote Management | Može utjecati na udaljenu administraciju |
| `Set-LLMNR` | Upravlja protokolom rezolucije imena | Obično je sigurno za onemogućavanje |
| `Set-NetBIOS` | Kontroliše NetBIOS preko TCP/IP | Može utjecati na legacy aplikacije |
| `Set-AdminShares` | Upravlja administrativnim dijeljenjem | Može utjecati na udaljeni pristup datotekama |
| `Set-Telemetry` | Kontroliše prikupljanje podataka | Može utjecati na dijagnostičke sposobnosti |
| `Set-GuestAccount` | Upravlja gostujućim računom | Obično je sigurno za onemogućavanje |
| `Set-ICMP` | Kontroliše ping odgovore | Može utjecati na mrežnu dijagnostiku |
| `Set-RemoteAssistance` | Upravlja udaljenom pomoći | Može utjecati na operacije help desk-a |
| `Set-NetworkDiscovery` | Kontroliše otkrivanje mreže | Može utjecati na pregledanje mreže |
| `Set-Firewall` | Upravlja Windows Firewall | Kritično za mrežnu sigurnost |

### Azure Cloud Sigurnost

| Funkcija | Svrha | Zahtjevi |
|----------|-------|----------|
| `Set-AzureSecurityDefaults` | Omogućava osnovnu Azure AD sigurnost | Microsoft Graph dozvole |
| `Set-AzureConditionalAccess` | Konfigurira politike pristupa | Azure AD P1/P2 licenciranje |
| `Set-AzurePrivilegedUsers` | Auditira privilegovane račune | Global Admin dozvole |

### Opcije Korporativne Implementacije

| Metod | Slučaj Upotrebe | Zahtjevi |
|-------|-----------------|----------|
| **Direktno Izvršavanje** | Testiranje, mala okruženja | Lokalna admin prava |
| **Group Policy** | Domain okruženja | Domain admin, GP upravljanje |
| **Microsoft Intune** | Cloud-upravljani uređaji | Intune licenciranje, Graph API |

## 🚀 Brzi Početak

### Sigurnosna Procjena
```powershell
# Učitajte Ghost modul
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')

# Provjerite trenutnu sigurnosnu poziciju
Get-Ghost
```

### Osnovno Učvršćavanje (Prvo Testirajte)
```powershell
# Ključno učvršćavanje - prvo testirajte u laboratorijskom okruženju
Set-Ghost -SMBv1 -AutoRun -Macros

# Pregledajte promjene
Get-Ghost
```

### Korporativna Implementacija
```powershell
# Group Policy implementacija (domain okruženja)
Set-Ghost -SMBv1 -AutoRun -GroupPolicy

# Intune implementacija (cloud-upravljani uređaji)
Set-Ghost -SMBv1 -RDP -USBStorage -Intune
```

## 📋 Metodi Instalacije

### Opcija 1: Direktno Preuzimanje (Testiranje)
```powershell
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')
```

### Opcija 2: Instalacija Modula
```powershell
# Instalirajte iz PowerShell Gallery (kada je dostupno)
Install-Module Ghost -Scope CurrentUser
Import-Module Ghost
```

### Opcija 3: Korporativna Implementacija
```powershell
# Kopirajte na mrežnu lokaciju za Group Policy implementaciju
# Konfigurirajte Intune PowerShell skripte za cloud implementaciju
```

## 💼 Primjeri Slučajeva Upotrebe

### Mali Biznis
```powershell
# Osnovna zaštita s minimalnim utjecajem
Set-Ghost -SMBv1 -AutoRun -Macros -ICMP
```

### Zdravstveno Okruženje
```powershell
# HIPAA-usmjereno učvršćavanje
Set-Ghost -SMBv1 -RDP -USBStorage -AdminShares -Telemetry
```

### Financijske Usluge
```powershell
# Visoko-sigurnosna konfiguracija
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -PSRemoting -AdminShares
```

### Cloud-First Organizacija
```powershell
# Intune-upravljana implementacija
Connect-IntuneGhost -Interactive
Set-Ghost -SMBv1 -RDP -AutoRun -Macros -Intune
```

## 🔍 Detalji Funkcija

### Osnovne Funkcije Učvršćavanja

#### Mrežni Servisi
- **RDP**: Blokira pristup udaljenom radnom stolu ili randomizuje port
- **SMBv1**: Onemogućava legacy protokol dijeljenja datoteka
- **ICMP**: Sprečava ping odgovore za izviđanje
- **LLMNR/NetBIOS**: Blokira legacy protokole rezolucije imena

#### Sigurnost Aplikacija
- **Makroi**: Onemogućava izvršavanje makroa u Office aplikacijama
- **AutoRun**: Sprečava automatsko izvršavanje s uklonjivog medija

#### Udaljeno Upravljanje
- **PSRemoting**: Onemogućava PowerShell udaljene sesije
- **WinRM**: Zaustavlja Windows Remote Management
- **Remote Assistance**: Blokira konekcije udaljene pomoći

#### Kontrola Pristupa
- **Admin Shares**: Onemogućava C$, ADMIN$ shares
- **Guest Account**: Onemogućava pristup gostujućem računu
- **USB Storage**: Ograničava upotrebu USB uređaja

### Azure Integracija
```powershell
# Povezivanje na Azure tenant
Connect-AzureGhost -Interactive

# Omogućavanje sigurnosnih zadanih postavki
Set-AzureSecurityDefaults -Enable

# Konfiguriranje uvjetnog pristupa
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Auditiranje privilegovanih korisnika
Set-AzurePrivilegedUsers -AuditOnly
```

### Intune Integracija (Novo u v2)
```powershell
# Povezivanje na Intune
Connect-IntuneGhost -Interactive

# Implementacija putem Intune politika
Set-IntuneGhost -Settings @{
    RDP = $true
    SMBv1 = $true
    USBStorage = $true
    Macros = $true
}
```

## ⚠️ Važna Razmatranja

### Zahtjevi za Testiranje
- **Laboratorijsko Okruženje**: Testirajte sve postavke u izolovanom okruženju prvo
- **Poštapna Implementacija**: Postupno implementirajte da identificirate probleme
- **Plan Vraćanja**: Osigurajte da možete vratiti promjene ako je potrebno
- **Dokumentacija**: Zabilježite koje postavke rade za vaše okruženje

### Potencijalni Utjecaj
- **Produktivnost Korisnika**: Neke postavke mogu utjecati na dnevni tok rada
- **Legacy Aplikacije**: Stariji sistemi mogu zahtijevati određene protokole
- **Udaljeni Pristup**: Razmotriti utjecaj na legitimnu udaljenu administraciju
- **Poslovni Procesi**: Provjeriti da postavke ne narušavaju kritične funkcije

### Sigurnosna Ograničenja
- **Obrambena Dubina**: Ghost je jedan sloj sigurnosti, ne kompletno rješenje
- **Kontinuirano Upravljanje**: Sigurnost zahtijeva kontinuirano praćenje i ažuriranja
- **Obuka Korisnika**: Tehnička kontrola mora biti uparena sa sigurnosnom svješću
- **Evolucija Prijetnji**: Novi metodi napada mogu zaobići trenutnu zaštitu

## 🎯 Primjeri Scenarija Napada

Dok Ghost cilja na uobičajene vektore napada, specifična prevencija ovisi o pravilnoj implementaciji i testiranju:

### WannaCry-stil Napadi
- **Ublažavanje**: `Set-Ghost -SMBv1` onemogućava ranjivi protokol
- **Razmatranje**: Osigurajte da nijedan legacy sistem ne zahtijeva SMBv1

### RDP-bazirani Ransomware
- **Ublažavanje**: `Set-Ghost -RDP` blokira pristup udaljenom radnom stolu
- **Razmatranje**: Može zahtijevati alternativne metode udaljenog pristupa

### Malware Baziran na Dokumentima
- **Ublažavanje**: `Set-Ghost -Macros` onemogućava izvršavanje makroa
- **Razmatranje**: Može utjecati na legitimne dokumente s omogućenim makroima

### USB-dostavljene Prijetnje
- **Ublažavanje**: `Set-Ghost -USBStorage -AutoRun` ograničava USB funkcionalnost
- **Razmatranje**: Može utjecati na legitimnu upotrebu USB uređaja

## 🏢 Korporativne Značajke

### Group Policy Podrška
```powershell
# Primjenjivanje postavki putem Group Policy registra
Set-Ghost -SMBv1 -RDP -AutoRun -GroupPolicy

# Postavke se primjenjuju domenom-široko nakon GP osvježavanja
gpupdate /force
```

### Microsoft Intune Integracija
```powershell
# Kreiranje Intune politika za Ghost postavke
Set-IntuneGhost -Settings $GhostSettings -Interactive

# Politike se automatski implementiraju na upravljane uređaje
```

### Izvještavanje o Usklađenosti
```powershell
# Generiranje izvještaja sigurnosne procjene
Get-Ghost | Export-Csv -Path "SecurityAudit-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Azure izvještaj sigurnosne pozicije
Get-AzureGhost | Out-File "AzureSecurityReport.txt"
```

## 📚 Najbolje Prakse

### Pred-implementacija
1. **Dokumentiranje Trenutnog Stanja**: Pokrenite `Get-Ghost` prije promjena
2. **Temeljito Testiranje**: Validirajte u ne-produkcijskom okruženju
3. **Planiranje Povratka**: Znajte kako vratiti svaku postavku
4. **Pregled Dionika**: Osigurajte da poslovne jedinice odobravaju promjene

### Tijekom Implementacije
1. **Poštapni Pristup**: Implementirajte prvo u pilot grupama
2. **Praćenje Utjecaja**: Pazite na žalbe korisnika ili sistemske probleme
3. **Dokumentiranje Problema**: Zabilježite sve probleme za buduću referencu
4. **Komunikacija Promjena**: Informirajte korisnike o sigurnosnim poboljšanjima

### Post-implementacija
1. **Redovita Procjena**: Periodično pokretajte `Get-Ghost` da verificirate postavke
2. **Ažuriranje Dokumentacije**: Održavajte sigurnosne konfiguracije ažurnima
3. **Pregled Efikasnosti**: Praćenje sigurnosnih incidenata
4. **Kontinuirano Poboljšanje**: Prilagođavajte postavke na osnovu prijetnji

## 🔧 Rješavanje Problema

### Uobičajeni Problemi
- **Greške Dozvola**: Osigurajte povišenu PowerShell sesiju
- **Ovisnosti Servisa**: Neki servisi mogu imati ovisnosti
- **Kompatibilnost Aplikacija**: Testirajte s poslovnim aplikacijama
- **Mrežna Povezanost**: Verificirajte da udaljeni pristup još uvijek radi

### Opcije Oporavka
```powershell
# Ponovni omogući specifičnih servisa kad je potrebno
Set-RDP -Enable
Set-SMBv1 -Enable
Set-AutoRun -Enable
Set-Macros -Enable
```

## 👨‍💻 O Autoru

**Jim Tyler** - Microsoft MVP za PowerShell
- **YouTube**: [@PowerShellEngineer](https://youtube.com/@PowerShellEngineer) (10.000+ pretplatnika)
- **Newsletter**: [PowerShell.News](https://powershell.news) - Sedmična sigurnosna inteligencija
- **Autor**: "PowerShell for Systems Engineers"
- **Iskustvo**: Decenije PowerShell automatizacije i Windows sigurnosti

## 📄 Licenca i Odricanje

### MIT Licenca
Ghost se pruža pod MIT licencom za besplatnu upotrebu, modificiranje i distribuciju.

### Sigurnosno Odricanje
- **Nema Garancije**: Ghost se pruža "kako jeste" bez garancije bilo koje vrste
- **Testiranje Potrebno**: Uvijek testirajte u ne-produkcijskim okruženjima prvo
- **Profesionalno Usmjeravanje**: Konsultujte sigurnosne stručnjake za produkcijske implementacije
- **Operacijski Utjecaj**: Autori nisu odgovorni za bilo kakve operacijske prekide
- **Sveobuhvatna Sigurnost**: Ghost je jedna komponenta kompletne sigurnosne strategije

### Podrška
- **GitHub Problemi**: [Prijavite bugove ili zatražite funkcije](https://github.com/jimrtyler/Ghost/issues)
- **Dokumentacija**: Koristite `Get-Help <function> -Full` za detaljnu pomoć
- **Zajednica**: PowerShell i sigurnosni zajednički forumi

---

**🔐 Ojačajte svoju sigurnosnu poziciju s Ghost - ali uvijek prvo testirajte.**

```powershell
# Počnite s procjenom, ne pretpostavkama
Get-Ghost
```

**⭐ Označite ovaj repozitorij zvjezdicom ako Ghost pomaže poboljšati vašu sigurnosnu poziciju!**