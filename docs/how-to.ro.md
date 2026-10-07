# Awarely Scan: de la instalare la primul rezultat

Urmează traseul simplu: pregătești Linux, instalezi scannerul, alegi din meniu și citești rezultatul. Nu trebuie să știi Python sau să editezi JSON. Mesajele și comenzile CLI sunt în engleză. Exemplele sunt fictive și trebuie adaptate la calculatorul tău.

[English](how-to.md) · [Română](how-to.ro.md)

Release: `v0.9.0-alpha.1`

- [Începe aici: prima scanare în 4 pași](#start-here)
- [Start: instalare simplificată, o singură dată](#quick-install)
- [Actualizează Awarely și Syft gestionat de el](#scanner-updates)
- [Scanare ghidată: alegerile din meniu](#guided)
- [1. Alege fluxul](#choose)
- [2. Pregătește mașina Linux](#prerequisites)
- [GitHub CLI în sistem, opțional · alternativă manuală](#manual-verifier)
- [3. Descarcă, verifică și pornește · alternativă manuală](#install)
- [4. Debian · alternativă manuală](#debian)
- [4. Ubuntu · alternativă manuală](#ubuntu)
- [4. Rocky Linux · alternativă manuală](#rocky-linux)
- [4. AlmaLinux · alternativă manuală](#almalinux)
- [4. Amazon Linux 2023 · alternativă manuală](#amazon-linux-2023)
- [4. Amazon Linux 2 · alternativă manuală](#amazon-linux-2)
- [5. Alege ce colectezi · alternativă manuală](#scope)
- [6. Colectează o aplicație · alternativă manuală](#applications)
- [6b. Java și alte ecosisteme cu Syft opțional · alternativă manuală](#syft)
- [7. Importă SBOM-ul local în Monitor](#upload)
- [8. Creează și protejează un token de mașină](#credentials)
- [9. Verifică fără salvare · alternativă manuală](#check)
- [10. Sincronizează o sursă · alternativă manuală](#sync)
- [11. Citește rezultatele, exporturile și alertele](#results)
- [12. Scanează din nou după actualizare](#after-remediation)
- [13. Rotește, revocă și retrage o sursă](#credentials-lifecycle)
- [14. Limite și reîncercări](#limits)
- [15. Probleme uzuale și coduri de ieșire](#troubleshooting)

<a id="start-here"></a>

## Începe aici: prima scanare în 4 pași

Un SBOM este lista componentelor software și a versiunilor lor. Scanarea locală creează această listă; Check caută vulnerabilități, iar Sync salvează lista în Monitor. Pentru prima încercare, alege scanare Linux și păstrarea fișierului local: nu ai nevoie de cont sau cheie API.

1. Deschide terminalul pe mașina Linux de scanat. Dacă e un server, conectează-te prin SSH înainte. Nu rula instalarea Linux în terminalul macOS sau Windows.
2. Verifică uneltele de bază din secțiunea 2. Installerul simplificat își poate pregăti singur verificatorul temporar: nu trebuie să instalezi GitHub CLI (gh) sau să te autentifici în GitHub.
3. Instalează o singură dată folosind secțiunea de instalare simplificată. Continuă numai după mesajul READY. La fiecare utilizare ulterioară deschizi direct meniul.
4. Rulează comanda de mai jos. Alege 1 pentru Linux, Enter pentru selecția recomandată, un nume pentru inventar, Enter pentru director și 1 pentru fișier local. Păstrează calea afișată la Saved local SBOM.

```sh
"$HOME/.local/bin/awarely-scan" guided
```

Comenzile lungi marcate „alternativă manuală” sunt pentru automatizări. Nu trebuie executate după meniul ghidat. Nici directoarele /srv/demo-shop, /srv/demo-python sau /srv/demo-java nu sunt create de scanner: folosește directoarele aplicațiilor tale.


<a id="quick-install"></a>

## Start: instalare simplificată, o singură dată

Rulează pe Linux amd64/arm64 ca utilizator obișnuit. Unelte de bază: curl, tar, gzip, coreutils și awk. Nu trebuie să instalezi gh în sistem. Dacă lipsește sau este prea vechi, răspunde yes la Prepare the temporary verifier: installerul descarcă GitHub CLI 2.102.0 din release-ul oficial, verifică SHA-256 fixat în script și șterge fișierele temporare la ieșire. Pregătirea nu necesită root, configurarea unui repository, cont sau token.

Dacă lipsește o unealtă de bază, installerul o numește și afișează comenzile distribuției tale. Rulează-le într-un alt terminal, apoi apasă Enter în installer pentru reverificare. Acesta nu rulează sudo și nu modifică pachetele sistemului în locul tău. q închide procesul. Dacă lipsește curl, instalează-l înainte să descarci installerul.

Descarcă și citește installerul oficial (în less, apasă q pentru a ieși), apoi rulează-l. El verifică proveniența semnată pentru versiunea exactă și checksum-urile, apoi publică binarul în ~/.local/bin/awarely-scan. Dacă există o instalare mai veche, cere confirmarea actualizării și păstrează un backup privat pentru revenire. Nu muta și nu șterge binarul vechi. Un installer cu aceeași versiune sau una mai veche este refuzat. Dacă apare STOP, rezolvă cauza înainte de a rula scannerul.

```sh
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fL \
  https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/v0.9.0-alpha.1/install.sh \
  -o awarely-install.sh
# Review the installer before running it.
less awarely-install.sh
sh awarely-install.sh
"$HOME/.local/bin/awarely-scan" guided
```

După READY, nu mai ai de copiat comenzile pentru Syft/Cosign. Deschide meniul de fiecare dată cu comanda de mai jos. Dacă binarul este deja în PATH, poți folosi doar awarely-scan. Instalarea verificată manual și transferul de pe o stație de încredere rămân disponibile în secțiunea 3.

```sh
"$HOME/.local/bin/awarely-scan" guided
```


<a id="scanner-updates"></a>

## Actualizează Awarely și Syft gestionat de el

Disponibil din v0.9.0-alpha.1. Dacă scannerul tău nu recunoaște comanda update, rulează o dată installerul simplificat de mai sus și aprobă actualizarea. El verifică noul release înainte de a înlocui binarul existent. Rulează actualizarea cu utilizatorul care a instalat scannerul, fără sudo.

Verifică mai întâi ce versiune este disponibilă. Această comandă explicită contactează GitHub; nu instalează nimic, nu trimite inventarul și nu folosește o cheie API.

```sh
"$HOME/.local/bin/awarely-scan" update --check
```

Pentru instalare, rulează comanda următoare și scrie yes la Continue. Scannerul descarcă un verificator temporar cu versiune fixată, verifică proveniența semnată pentru repository-ul, workflow-ul și tagul exact, verifică amprenta și pornirea binarului, apoi înlocuiește atomic executabilul. Nu ai nevoie de cont GitHub sau gh instalat în sistem. Lasă terminalul deschis până la final.

```sh
"$HOME/.local/bin/awarely-scan" update
```

După mesajul Updated to, verifică ambele versiuni și continuă cu meniul ghidat. Scanările obișnuite nu caută actualizări și nu schimbă scannerul în fundal.

```sh
"$HOME/.local/bin/awarely-scan" version --tools
"$HOME/.local/bin/awarely-scan" guided
```

Syft se actualizează doar printr-un release Awarely testat. Acest release gestionează Syft 1.54.1; în meniul ghidat nu poți alege o versiune arbitrară sau latest. La următoarea scanare Syft, scannerul explică descărcarea și cere acordul. Arhiva este verificată față de SHA-256 inclus în binar la fiecare utilizare. Versiunile existente din cache sunt păstrate pentru revenirea la versiunea anterioară. Poți importa în continuare SBOM-uri produse separat, dar acestea nu intră în garanția verificării utilitarului gestionat.

Dacă noul scanner creează o problemă, revino la unicul binar anterior cu comanda de mai jos și răspunde yes. Revenirea folosește backupul privat local, fără descărcare. Restaurează CLI-ul anterior și versiunea Syft asociată; inventarele, rapoartele și credentialele rămân intacte. O versiune mai veche de v0.9.0-alpha.1 nu are comanda update: folosește installerul oficial curent pentru a actualiza din nou.

```sh
"$HOME/.local/bin/awarely-scan" update --rollback
```

Instalările stabile primesc doar versiuni stabile. O instalare prerelease vede și prerelease-uri mai noi. Opțiuni avansate: update --version v0.9.0-alpha.1 alege un release publicat mai nou, exact; update --prerelease include explicit preview-uri; update --yes elimină confirmarea pentru automatizări controlate. Revenirea la o versiune mai veche se face prin rollback. update --help afișează opțiunile.

La o eroare de descărcare, verificare, permisiuni sau pornire, rezolvă cauza afișată și reîncearcă; nu ocoli verificarea. Codul de ieșire 7 indică o eroare de actualizare. Dacă rulează alt update, așteaptă. Dacă mesajul spune că binarul a fost înlocuit, dar scrierea directorului pe disc a eșuat, verifică version înainte de a reîncerca. Actualizarea cere un executabil real numit awarely-scan, într-un director deținut de utilizator, cu directoare părinte de încredere, fără drepturi de scriere pentru alți utilizatori; instalările prin link simbolic sunt refuzate.


<a id="guided"></a>

## Scanare ghidată: alegerile din meniu

| Alegere | Ce introduci | Ce verifică scannerul |
| --- | --- | --- |
| 1. Linux | Focused (1) / All packages (2) | Detectează distribuția și citește baza pachetelor; fără root sau instalare de unelte. |
| 2. npm | /srv/demo-shop → 1 (native) / 2 (Syft) | Caută lockfile v2/v3 sau package.json; Node.js/npm nu este necesar pentru citire. Nu rulează npm install. |
| 3. Python | /srv/demo-python → 1 (requirements.txt) / 2 (installed environment) | Modul 1 este parțial; modul 2 cere metadatele unei .venv existente și poate pregăti Syft. |
| 4. Java | /srv/demo-java | Cere artefacte JAR/WAR/EAR existente; nu instalează Java/Maven și nu construiește proiectul. |
| 5. Other ecosystems | /srv/my-app | Syft pentru NuGet/Go/Composer/RubyGems/Cargo. Inventar și sync disponibile; CVE neevaluat. |
| 6. SBOM existent | /home/demo-user/awarely-results-EXAMPLE/inventory.cdx.json | Deschide un inventar Awarely salvat pentru Check/Sync; fără o nouă scanare. |

Meniul are 3 etape: alegerea scanării, salvarea locală și alegerea acțiunii. Enter acceptă valoarea dintre [paranteze]. b revine la pasul anterior; q închide păstrând fișierele deja salvate. Culorile apar numai în terminal; mesajele rămân lizibile și fără culori. Pentru dezactivare: NO_COLOR=1 "$HOME/.local/bin/awarely-scan" guided.

Introdu o cale existentă. Sunt acceptate ~/my-app, căile relative și căile între ghilimele. Dacă greșești calea sau alegi un fișier în locul directorului, scannerul explică problema și cere o nouă cale. Nu execută comenzile introduse. Pentru Syft, yes aprobă descărcarea versiunii fixate (~30 MB), verificarea și rularea locală. Cache-ul privat este reverificat la fiecare utilizare; nu sunt necesare Cosign sau autentificare GitHub. Nu instalează dependențe și nu construiește proiectul.

După scanare, alege un nume de aplicație și directorul părinte pentru rezultate (Enter păstrează directorul home). Scannerul creează un folder privat awarely-results-... și afișează calea completă către inventory.cdx.json. Fiecare scanare are propriul folder, deci nu trebuie să inventezi nume noi. Nu trimite încă inventarul.

1. Alege 1 sau apasă Enter: păstrează fișierul local. Pentru upload, urmează secțiunea 7.
2. Alege 2: verificare API. Creează credențiala conform secțiunii 8, transfer-o în afara proiectului, aplică chmod 600 și introdu calea fișierului. Meniul afișează destinația, aplicația și sursa; confirmă yes. Primești check-result.json în același folder și un rezumat în terminal. Inventarul salvat și alertele nu se modifică.
3. Alege 3: sincronizare API. Este disponibilă numai pentru inventare complete. Verifică sursa afișată și confirmă yes: numai acea sursă este înlocuită imediat. Primești sync-result.json. Alertele viitoare urmează preferințele salvate; nu se trimit emailuri retroactive.
4. Dacă lipsește tokenul sau nu dorești operația, introdu q ori răspunde no. Fișierul local deja creat rămâne disponibil. Reia oricând meniul pentru o nouă scanare.

Exemplu npm: 2 → /srv/demo-shop → 1 → demo-shop → Enter → 1. Exemplu Java: 4 → /srv/demo-java → yes → demo-java → Enter → 1. Pentru Python cu pachete instalate: 3 → /srv/demo-python → 2 → yes → demo-python → Enter → 1. Linux: 1 → 1 → test-linux → Enter → 1.

Exit code 3 înseamnă că s-a scris un inventar parțial, nu că s-a găsit un CVE. Codul 0 nu garantează absența vulnerabilităților. Examinează versiunile, precizia și componentele neevaluate din raport. Comenzile din secțiunile următoare sunt alternative pentru automatizări; nu trebuie rulate în plus față de meniu.

Un Check reușit creează check-result.json cu dovezile complete și check-summary.txt, un rezumat text cu toate potrivirile și componentele neevaluate. Terminalul arată primele 10 potriviri componentă–CVE. Deschide fișierul text cu less /cale/catre/check-summary.txt; q închide vizualizarea. Zero potriviri nu înseamnă că aplicația este sigură; verifică și acoperirea și componentele neevaluate.

Dacă fișierul de acces este greșit, introdu altă cale fără să rescanezi. După o eroare Check poți reîncerca cu o nouă confirmare. După o eroare Sync, verifică sursa în Setări → Active înainte de reluare: cererea ar putea fi deja aplicată. Scannerul nu repetă automat o sincronizare incertă. Pentru reluare mai târziu, alege opțiunea 6 și SBOM-ul salvat.

Binarul nu are nevoie de gh, Cosign, Node.js, Java sau Python pentru a citi fișierele suportate. Dacă lipsesc manifestele/artefactele, poți corecta directorul în același meniu. Dacă descărcarea Syft aprobată eșuează temporar, restabilește accesul HTTPS și alege Retry preparation: aplicația selectată se păstrează. Erorile de integritate sau cache nesigur opresc fluxul: nu se execută un instrument neverificat.


<a id="choose"></a>

## 1. Alege fluxul

| Mod | Cont / plan | Ce se întâmplă |
| --- | --- | --- |
| Fișier local | Fără cont; CLI Apache-2.0 | host/app scrie local JSON CycloneDX 1.6. Fără rețea sau evaluare CVE. |
| Upload în Active | Monitor Pro sau trial Pro activ | Verifici SBOM-ul în browser, aplici modificările și apeși Salvează. |
| Verificare API | Acces Pro + token Doar verificare | Primești un raport JSON local. Nu salvează inventarul și nu trimite alerte. |
| Sincronizare API | Acces Pro + token Doar sincronizare sau ambele | Înlocuiește imediat doar sursa autorizată din inventarul salvat. |

Versiunea este un API preview. Același utilitar, compilat pentru amd64 sau arm64, detectează distribuțiile de mai jos. Integrarea Jenkins, containerele, imaginile AMI/VHD, Alpine și scanarea binarelor arbitrare nu sunt disponibile. Este acceptat un director cu un sistem de fișiere Linux offline; nu un fișier imagine.

Flux recomandat: instalare simplificată → scanare ghidată → alege ce faci cu rezultatul. Pentru API, pregătește credențiala conform secțiunii 8. Secțiunile pe distribuții și comenzile lungi sunt alternative manuale, nu pași obligatorii ai meniului.


<a id="prerequisites"></a>

## 2. Pregătește mașina Linux

Rulează verificările pe mașina Linux de scanat. sudo este necesar numai dacă lipsesc unelte de bază. Binarul Awarely rulează ca utilizator obișnuit. curl descarcă prin HTTPS; ca-certificates validează certificatele; tar/gzip extrag arhive; coreutils și awk verifică sumele de control. Installerul simplificat se ocupă de gh.

```sh
uname -m
cat /etc/os-release
for tool in curl tar gzip sha256sum awk mktemp; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "OK: %s\n" "$tool"
  else
    printf "MISSING: %s\n" "$tool"
  fi
done
```

Dacă lipsesc unelte, alege numai distribuția ta de mai jos. Dacă toate verificările spun OK, continuă la instalarea simplificată. Nu este necesară instalarea pachetului gh sau autentificarea GitHub.

Debian / Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl tar gzip coreutils gawk
```

Amazon Linux 2023 / Rocky Linux / AlmaLinux:

```sh
sudo dnf install -y ca-certificates tar gzip coreutils gawk
command -v curl >/dev/null || sudo dnf install -y curl
```

Amazon Linux 2:

```sh
sudo yum install -y ca-certificates tar gzip coreutils gawk
command -v curl >/dev/null || sudo yum install -y curl
```

Numai pentru verificarea manuală: secțiunea GitHub CLI în sistem, opțional de mai jos explică instalarea gh. Nu este necesară pentru installerul recomandat.


<a id="manual-verifier"></a>

## GitHub CLI în sistem, opțional · alternativă manuală

Sari peste această secțiune pentru instalarea simplificată. Folosește-o numai dacă preferi gh instalat în sistem sau verificarea manuală. Amazon Linux suportă gh prin repository-ul oficial GitHub; repository-urile implicite pot să nu îl conțină.

Rulează pașii 2–3 în aceeași sesiune Bash, ca utilizator Linux obișnuit. sudo este necesar doar pentru instalarea utilitarelor; Awarely Scan nu necesită root sau serviciu în fundal. Ai nevoie de citire pentru pachete/proiect și de scriere în directorul de rezultate.

Mai întâi identifică sistemul și comenzile disponibile. Acest bloc doar verifică: MISSING înseamnă că trebuie să instalezi utilitarul folosind blocul distribuției tale de mai jos.

```sh
uname -m
cat /etc/os-release
for tool in curl tar sha256sum awk gh; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'OK: %s\n' "$tool"
  else
    printf 'MISSING: %s\n' "$tool"
  fi
done
if command -v gh >/dev/null 2>&1; then
  gh --version
  gh attestation verify --help
fi
```

| Comandă / utilitar | La ce folosește și ce faci dacă lipsește |
| --- | --- |
| uname -m | Arhitectura: x86_64 → amd64; aarch64/arm64 → arm64. Alte arhitecturi nu au binar publicat. |
| cat /etc/os-release | Distribuția și versiunea: ID și VERSION_ID îți arată ce bloc de instalare alegi. Dacă fișierul lipsește, nu ghici distribuția; verifică imaginea cu administratorul. |
| curl + ca-certificates | Descarcă fișiere prin HTTPS și validează certificatul serverului. Se instalează mai jos; nu folosi curl -k. |
| tar | Extrage arhiva verificată. Instalează pachetul tar dacă lipsește. |
| sha256sum / coreutils | Verifică integritatea fișierelor. Comanda face parte din coreutils; acesta furnizează și uname, mktemp și chmod. |
| awk | Selectează checksum-ul arhivei tale. Dacă lipsește, blocul distribuției instalează gawk. |
| gh attestation verify | Verifică proveniența build-ului folosind dovada semnată descărcată public. Nu cere cont, login sau token GitHub. gh absent: instalează mai jos. unknown command/unknown flag: actualizează din depozitul oficial și repetă verificarea. |

Alege un singur bloc, după distribuție. Dacă toate utilitarele există și gh attestation verify --help funcționează, sari direct la pasul 3. Comenzile configurează depozitul oficial GitHub CLI și instalează utilitarele necesare; nu instalează scannerul și nu fac un upgrade general al sistemului.

Debian 12/13 și Ubuntu 22.04/24.04/26.04 — apt. apt-get update reîncarcă lista pachetelor, iar install adaugă sau actualizează numai pachetele cerute. Cheia și intrarea signed-by permit APT să verifice pachetele din depozitul GitHub CLI.

```sh
(
set -eu
# Refresh package metadata and install download/verification tools.
sudo apt-get update
sudo apt-get install -y ca-certificates curl tar coreutils
command -v awk >/dev/null || sudo apt-get install -y gawk
# Add the signing key for the official GitHub CLI package repository.
GH_KEY_FILE=$(mktemp)
trap 'rm -f "$GH_KEY_FILE"' EXIT
curl --proto '=https' --tlsv1.2 -fL \
  https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  -o "$GH_KEY_FILE"
sudo install -d -m 755 /etc/apt/keyrings
sudo install -m 644 "$GH_KEY_FILE" /etc/apt/keyrings/githubcli-archive-keyring.gpg
rm "$GH_KEY_FILE"
# Configure the source for this machine architecture; its key is scoped to this source.
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' "$(dpkg --print-architecture)" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update
# Install gh or upgrade an older installed version.
sudo apt-get install -y gh
)
```

Un mesaj precum «1 upgraded» pentru gh este normal: versiunea veche a fost înlocuită. «0 newly installed» nu înseamnă eroare. Continuă dacă blocul se încheie fără eroare, apoi repetă verificarea gh de mai jos.

Rocky Linux 8/9/10, AlmaLinux 8/9/10 și Amazon Linux 2023 — dnf. Utilitarele sunt instalate, config-manager adaugă depozitul oficial GitHub CLI, apoi se instalează gh. Verifică versiunea DNF și alege numai unul dintre cele două blocuri.

```sh
dnf --version
```

Pentru DNF 4:

```sh
(
set -eu
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils 'dnf-command(config-manager)'
sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo dnf install -y gawk
sudo dnf install -y gh
sudo dnf upgrade -y gh
)
```

Pentru DNF 5, în locul blocului DNF 4:

```sh
(
set -eu
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils dnf5-plugins
sudo dnf config-manager addrepo --from-repofile=https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo dnf install -y gawk
sudo dnf install -y gh
sudo dnf upgrade -y gh
)
```

Amazon Linux 2 — yum. yum-utils furnizează comanda pentru adăugarea depozitului GitHub CLI; restul utilitarelor au același rol. Awarely acceptă inventar/sync pentru această distribuție; evaluarea CVE rămâne indisponibilă.

```sh
(
set -eu
command -v curl >/dev/null || sudo yum install -y curl
sudo yum install -y ca-certificates tar coreutils yum-utils
sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
command -v awk >/dev/null || sudo yum install -y gawk
sudo yum install -y gh
sudo yum update -y gh
)
```

Acum verifică versiunea și suportul pentru atestări. Dacă încă apare unknown command, verifică command -v gh: este posibil să rulezi o altă instalare mai veche din PATH.

```sh
command -v gh
gh --version
gh attestation verify --help
```

Nu rula gh auth login și nu crea un token GitHub pentru această instalare. La pasul 3, gh primește dovada semnată prin --bundle și o verifică fără autentificare. Descărcarea și actualizarea rădăcinilor de încredere folosesc internetul; colectarea locală host/app nu. Pentru un server offline, verifică pe o stație de încredere și transferă securizat fișierele verificate.

- [Instalare oficială GitHub CLI](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)
- [Verificarea unei dovezi locale cu --bundle](https://cli.github.com/manual/gh_attestation_verify)


<a id="install"></a>

## 3. Descarcă, verifică și pornește · alternativă manuală

Comenzile fixează versiunea preview publicată. Oprește-te la orice eroare de descărcare, atestare sau checksum. Lista externă include ambele arhitecturi; verificăm doar arhiva descărcată. Extragerea se face după verificare.

Fără cont GitHub și fără token. Descărcăm arhiva originală și dovada semnată din același release public. Dovada este verificată criptografic pentru arhiva exactă, repo-ul Awarely, workflow-ul de release și tag-ul ales, înainte de extragere.

umask 077 și mktemp creează un director privat nou; SCAN_WORK păstrează calea acestuia. Înainte de descărcare se verifică utilitarele. Nu ai nevoie de autentificare GitHub. curl descarcă arhiva și dovada semnată, gh --bundle validează proveniența pentru repo/workflow/tag, awk selectează checksum-ul potrivit, sha256sum verifică integritatea, iar tar extrage numai după verificări. version și help confirmă că binarul pornește. SCAN_BIN este setat numai dacă întregul bloc reușește.

```sh
SCAN_BIN=
umask 077
SCAN_WORK=$(mktemp -d "$HOME/awarely-scan.XXXXXXXX")
(
set -eu
: "${SCAN_WORK:?Could not create working directory}"
for tool in curl tar sha256sum awk gh; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
done
gh attestation verify --help >/dev/null || { echo 'STOP: update GitHub CLI (step 2).' >&2; exit 1; }
cd "$SCAN_WORK"
SCAN_VERSION=v0.9.0-alpha.1
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_RELEASE="https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/${SCAN_VERSION}"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE" -o "$SCAN_ARCHIVE"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/SHA256SUMS" -o SHA256SUMS
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE.sigstore.jsonl" -o "$SCAN_ARCHIVE.sigstore.jsonl"
gh attestation verify "$SCAN_ARCHIVE" \
  --bundle "$SCAN_ARCHIVE.sigstore.jsonl" \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml \
  --source-ref "refs/tags/$SCAN_VERSION"
awk -v file="$SCAN_ARCHIVE" '$2 == file { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum --check selected-SHA256SUMS
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
"$SCAN_WORK/release/awarely-scan" version
"$SCAN_WORK/release/awarely-scan" help
printf 'Working directory: %s\n' "$SCAN_WORK"
)
SCAN_INSTALL_STATUS=$?
if [ "$SCAN_INSTALL_STATUS" -eq 0 ]; then
  SCAN_BIN="$SCAN_WORK/release/awarely-scan"
  printf 'READY: %s\n' "$SCAN_BIN"
else
  SCAN_BIN=
  printf 'STOP: installation incomplete in %s. Fix the error and rerun all of step 3. Do not scan yet.\n' "$SCAN_WORK" >&2
  (exit "$SCAN_INSTALL_STATUS")
fi
```

Păstrează SCAN_WORK și SCAN_BIN pentru pașii următori. Fiecare cale de rezultat trebuie să fie nouă: scannerul nu suprascrie rapoarte. Folosește un director privat nou la următoarea rulare. O versiune viitoare se descarcă și se verifică explicit; nu există actualizare automată.

Dacă deschizi ulterior alt terminal, setează calea reală afișată mai sus: SCAN_WORK=/home/utilizator/awarely-scan.DIRECTORUL_TAU și SCAN_BIN="$SCAN_WORK/release/awarely-scan". Înlocuiește calea exemplu; nu crea altă sursă doar pentru că s-a schimbat sesiunea de terminal.

Continuă la pasul 4 sau 6 numai după mesajul READY, versiunea afișată și pagina de ajutor. Dacă apare STOP, nu rula host/app/check/sync. După remediere, copiază din nou TOT blocul de la pasul 3: acesta creează un director nou, păstrează fișierele vechi și actualizează variabilele. Doar fișierele .tar.gz și SHA256SUMS într-un director înseamnă că instalarea nu a ajuns la extragere.


<a id="debian"></a>

## 4. Debian · alternativă manuală

Versiuni de inventar acceptate: 12, 13; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name debian-13-web-01 \
  --output "$SCAN_WORK/debian-13-web-01.cdx.json"
```

Avizele oficiale Debian folosesc identitatea pachetului sursă și ordinea versiunilor Debian, inclusiv epoch și revizia distribuției. Build-urile terților și depozitele backports necesită evaluare separată.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/debian-13-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/debian-13-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.receipt.json"
```


<a id="ubuntu"></a>

## 4. Ubuntu · alternativă manuală

Versiuni de inventar acceptate: 22.04, 24.04, 26.04 LTS; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name ubuntu-24-04-web-01 \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json"
```

Datele oficiale Ubuntu sunt evaluate după pachetul sursă și versiunea distribuției. Unele remedieri necesită Ubuntu Pro; Awarely nu stabilește dreptul tău de acces. Evaluările neconcludente rămân pentru analiză. PPA-urile și canalele specializate sunt în afara evaluării.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.receipt.json"
```


<a id="rocky-linux"></a>

## 4. Rocky Linux · alternativă manuală

Versiuni de inventar acceptate: 8, 9, 10; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name rocky-9-web-01 \
  --output "$SCAN_WORK/rocky-9-web-01.cdx.json"
```

Eratele oficiale Rocky folosesc numele pachetului binar, arhitectura, epoch/version/release RPM și fluxul de modul, când există. EPEL, furnizorii terți și pachetele absente din catalog rămân neevaluate. Remedierile publicate nu acoperă toate problemele încă neremediate.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/rocky-9-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/rocky-9-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.receipt.json"
```


<a id="almalinux"></a>

## 4. AlmaLinux · alternativă manuală

Versiuni de inventar acceptate: 8, 9, 10; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name alma-9-web-01 \
  --output "$SCAN_WORK/alma-9-web-01.cdx.json"
```

Eratele oficiale AlmaLinux folosesc numele pachetului binar, arhitectura, epoch/version/release RPM și fluxul de modul. Un pachet din altă distribuție RPM nu este tratat ca AlmaLinux. EPEL și furnizorii necunoscuți rămân neevaluate.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/alma-9-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/alma-9-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.receipt.json"
```


<a id="amazon-linux-2023"></a>

## 4. Amazon Linux 2023 · alternativă manuală

Versiuni de inventar acceptate: 2023; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name al2023-web-01 \
  --output "$SCAN_WORK/al2023-web-01.cdx.json"
```

Avizele oficiale ALAS pentru depozitul core sunt comparate cu versiunile RPM instalate. NVIDIA, Extras, pachetele terților și starea livepatch sunt în afara evaluării. Un depozit fixat pe un release poate necesita selectarea unui release mai nou pentru pachetul remediat.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/al2023-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2023-web-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.receipt.json"
```


<a id="amazon-linux-2"></a>

## 4. Amazon Linux 2 · alternativă manuală

Versiuni de inventar acceptate: 2; Linux amd64/arm64. Parcurge întâi pașii 2–3. Distribuția este detectată automat; nu există opțiune --distro sau instalator separat.

```sh
"$SCAN_BIN" host --name al2-legacy-01 \
  --output "$SCAN_WORK/al2-legacy-01.cdx.json"
```

Doar inventar și sincronizare: versiunea actuală nu evaluează pachetele AL2 față de avizele CVE AL2. check întoarce explicit o lipsă de acoperire de tip end-of-life/neevaluat. Zero potriviri nu înseamnă un rezultat de securitate curat. Folosește o evaluare separată și planifică migrarea.

Pentru utilizare exclusiv locală te oprești aici sau imporți fișierul .cdx.json la pasul 7. Pentru API, creează și protejează credentialele conform pasului 8, apoi alege o comandă de mai jos. Pentru ambele comenzi ai nevoie de permisiunea Verificare și sincronizare; Doar verificare permite numai prima. Interpretează raportul conform pasului 11.

Doar verificare (fără modificarea inventarului salvat):

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/al2-legacy-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2-legacy-01.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.receipt.json"
```


<a id="scope"></a>

## 5. Alege ce colectezi · alternativă manuală

Profilul host implicit selectează software uzual de server și dependențele instalate asociate. Nu colectează toate pachetele OS. Pentru DEB include nginx/apache2, OpenSSL, SSH, Node.js, Python, PHP, Java, baze de date și runtime-uri de containere; RPM folosește nume precum httpd. Absența unor membri opționali ai profilului implicit este acceptată.

```sh
"$SCAN_BIN" host --select 'nginx*,openssl,openssh-server' \
  --name demo-web --output "$SCAN_WORK/selected.cdx.json"

"$SCAN_BIN" host --all-packages \
  --name demo-full --output "$SCAN_WORK/all-packages.cdx.json"

"$SCAN_BIN" host --root /srv/offline-linux-root \
  --name demo-offline --output "$SCAN_WORK/offline.cdx.json"
```

Alege un singur mod: --select și --all-packages nu se combină. Un selector personalizat fără rezultat ori dependențele nerezolvate produc inventar parțial (exit 3). Dacă baza de pachete se schimbă, reîncearcă după terminarea managerului de pachete. Nu modifica baza RPM/dpkg și nu inventa metadate. Directorul offline trebuie să fie deja montat și lizibil; CLI-ul nu montează și nu extrage imagini.


<a id="applications"></a>

## 6. Colectează o aplicație · alternativă manuală

Pe orice gazdă Linux acceptată, alege directorul proiectului cu npm-shrinkwrap.json sau package-lock.json v2/v3. Sunt citite și package.json ca fallback și requirements.txt, însă acestea sunt întotdeauna parțiale. Nu se execută npm install, pip install sau scripturi ale proiectului.

```sh
"$SCAN_BIN" app --path /srv/demo-shop --name demo-shop \
  --output "$SCAN_WORK/demo-shop.cdx.json"
```

Lockfile-urile includ versiunile rezolvate pentru intrările directe/tranzitive, de dezvoltare și opționale; nu dovedesc instalarea sau deployment-ul. Linkurile workspace nu sunt urmărite. requirements.txt păstrează versiunile declarate; nu urmărește include-uri, URL-uri sau rezolvarea dependențelor. Fișierele parțiale pot fi analizate/importate ori verificate, dar sync le refuză. Nu sunt acceptate lockfile-uri pnpm/yarn/poetry sau descoperirea automată a monorepo-urilor.

Pentru colectare extinsă cu Syft, vezi pasul 6b.


<a id="syft"></a>

## 6b. Java și alte ecosisteme cu Syft opțional · alternativă manuală

În meniul ghidat, Awarely pregătește și verifică Syft după acordul tău: nu ai nevoie de Cosign sau de comenzile de mai jos. Aceste instrucțiuni sunt doar pentru instalarea și utilizarea separată a Syft.

Syft este un instrument Anchore separat, Apache-2.0. În fluxul manual îl rulezi separat; în meniul ghidat, Awarely îl poate pregăti și rula după confirmare. Folosește-l pentru colectarea care lipsește din modul nativ, apoi importă fișierul CycloneDX JSON 1.4–1.7. Sunt acceptate și fișiere compatibile produse de pluginurile CycloneDX Maven/Gradle. Importul nu execută build-uri, cod Java sau arhive.

| Ecosistem | Inventar / sync | Verificare CVE |
| --- | --- | --- |
| Java / Maven | Da | Versiuni Maven și coordonate complete |
| npm, Python / PyPI | Da | Intervale comparabile; restul necesită revizuire |
| .NET / NuGet, Go, PHP / Composer, RubyGems, Rust / Cargo | Da | Neevaluat în această versiune |

Parcurge întâi pașii 2–3 și păstrează aceeași sesiune Bash: SCAN_WORK și SCAN_BIN trebuie să indice instalarea reușită. Rulează în ordine cele trei blocuri de mai jos: A — Cosign, B — Syft, C — colectare Java. Descărcarea și verificarea necesită internet, dar nu necesită cont GitHub, token, sudo sau modificarea PATH.

A. Instalează și verifică Cosign. Acest utilitar verifică semnătura distribuției Syft. Descărcăm Cosign 3.1.3 din release-ul oficial și comparăm binarul cu SHA-256 fixat pentru arhitectura ta înainte de prima execuție. Valorile au fost comparate cu lista oficială de checksum-uri; nu le înlocui pentru a ocoli o eroare. Binarul verificat validează apoi și dovada Sigstore a propriei distribuții. Instalarea este în SCAN_WORK, iar COSIGN_BIN este setat numai după succes.

- [Cosign 3.1.3 — official release](https://github.com/sigstore/cosign/releases/tag/v3.1.3)
- [Cosign — installation and verification](https://docs.sigstore.dev/cosign/system_config/installation/)

```sh
COSIGN_BIN=
umask 077
COSIGN_DIR=$(mktemp -d "${SCAN_WORK:?STOP: complete step 3 first}/cosign-3.1.3.XXXXXXXX")
(
  set -eu
  : "${COSIGN_DIR:?STOP: could not create the Cosign directory}"
  for tool in curl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
  done
  COSIGN_VERSION=3.1.3
  case "$(uname -m)" in
    x86_64) COSIGN_ARCH=amd64; COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
    aarch64|arm64) COSIGN_ARCH=arm64; COSIGN_SHA256=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
    *) echo 'STOP: unsupported architecture' >&2; exit 1 ;;
  esac
  cd "$COSIGN_DIR"
  BASE="https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION"
  curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "$BASE/cosign-linux-$COSIGN_ARCH" -o cosign
  printf '%s  cosign\n' "$COSIGN_SHA256" > selected.sha256
  sha256sum --check selected.sha256
  chmod 700 cosign
  curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 \
    "$BASE/cosign-linux-$COSIGN_ARCH.sigstore.json" -o cosign.sigstore.json
  ./cosign verify-blob cosign --bundle cosign.sigstore.json \
    --certificate-identity keyless@projectsigstore.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com
  ./cosign version
)
COSIGN_INSTALL_STATUS=$?
if [ "$COSIGN_INSTALL_STATUS" -eq 0 ]; then
  COSIGN_BIN="$COSIGN_DIR/cosign"
  printf 'READY: %s\n' "$COSIGN_BIN"
else
  COSIGN_BIN=
  echo 'STOP: Cosign installation incomplete. Fix the error and rerun this entire block.' >&2
  (exit "$COSIGN_INSTALL_STATUS")
fi
```

Continuă numai după verificările reușite, versiunea v3.1.3 și mesajul READY. Nu trebuie să poți rula cosign ca o comandă simplă: în acest ghid îl apelăm prin calea completă din COSIGN_BIN.

B. Instalează și verifică Syft 1.54.1. Folosim Cosign din blocul A pentru semnătura listei de checksum-uri Anchore, apoi verificăm arhiva înainte de extragere. Dacă lipsește Cosign, blocul se oprește înainte de descărcări. SYFT_BIN este setat numai după verificare și pornire reușită.

- [Syft — release verification](https://oss.anchore.com/docs/installation/verification/)

```sh
SYFT_BIN=
umask 077
SYFT_DIR=$(mktemp -d "${SCAN_WORK:?STOP: complete step 3 first}/syft-1.54.1.XXXXXXXX")
(
  set -eu
  : "${SYFT_DIR:?STOP: could not create the Syft directory}"
  test -n "${COSIGN_BIN:-}" && test -x "$COSIGN_BIN" || { echo 'STOP: complete the Cosign block above first.' >&2; exit 1; }
  for tool in curl tar sha256sum awk; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'STOP: missing %s. Complete step 2.\n' "$tool" >&2; exit 1; }
  done
  SYFT_VERSION=1.54.1
  case "$(uname -m)" in
    x86_64) SYFT_ARCH=amd64 ;;
    aarch64|arm64) SYFT_ARCH=arm64 ;;
    *) echo 'STOP: unsupported architecture' >&2; exit 1 ;;
  esac
  cd "$SYFT_DIR"
  BASE="https://github.com/anchore/syft/releases/download/v$SYFT_VERSION"
  ARCHIVE="syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz"
  CHECKSUMS="syft_${SYFT_VERSION}_checksums.txt"
  for FILE in "$ARCHIVE" "$CHECKSUMS" "$CHECKSUMS.sigstore.json"; do
    curl --fail --location --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' --tlsv1.2 "$BASE/$FILE" -o "$FILE"
  done
  "$COSIGN_BIN" verify-blob "$CHECKSUMS" --bundle "$CHECKSUMS.sigstore.json" \
    --certificate-identity 'https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
  awk -v file="$ARCHIVE" '$2 == file {print; count++} END {if (count != 1) exit 1}' "$CHECKSUMS" > selected.sha256
  sha256sum --check selected.sha256
  tar -xzf "$ARCHIVE" syft
  chmod 700 syft
  ./syft version
)
SYFT_INSTALL_STATUS=$?
if [ "$SYFT_INSTALL_STATUS" -eq 0 ]; then
  SYFT_BIN="$SYFT_DIR/syft"
  printf 'READY: %s\n' "$SYFT_BIN"
else
  SYFT_BIN=
  echo 'STOP: Syft installation incomplete. Fix the error and rerun this entire block. Do not scan yet.' >&2
  (exit "$SYFT_INSTALL_STATUS")
fi
```

Continuă numai după versiunea 1.54.1 și READY. Pentru cosign: command not found sau syft: No such file or directory din instrucțiunile vechi, rulează întâi blocul A, apoi blocul B actualizat. Fiecare rulare folosește un director privat nou; nu șterge și nu suprascrie fișierele descărcate anterior. SCAN_WORK, SCAN_BIN și SBOM-urile existente rămân aceleași. Dacă deschizi alt terminal, restabilește SCAN_WORK și SCAN_BIN conform pasului 3, apoi COSIGN_BIN și SYFT_BIN folosind căile READY afișate aici, sau repetă blocurile A–B.

C. Colectează aplicația Java și importă rezultatul în Awarely. Acest pas începe numai după cele două mesaje READY.

Exemplu Java: /srv/demo-java conține artefactele JAR/WAR ale aplicației sau gradle.lockfile după build. Folosește artefactele efectiv livrate. Un pom.xml izolat poate avea versiuni moștenite și nu reprezintă întregul arbore rezolvat. Pentru proiecte Maven fără artefacte, generează SBOM-ul în build-ul tău de încredere cu pluginul CycloneDX și treci direct la comanda import.

```sh
# Select only the application directory you intend to inventory.
# Keep configuration and output outside that directory.
cat > "$SCAN_WORK/syft-config.yaml" <<'YAML'
check-for-app-update: false
enrich: []
java:
  use-network: false
  use-maven-local-repository: false
golang:
  use-packages-lib: false
  search-remote-licenses: false
javascript:
  search-remote-licenses: false
python:
  search-remote-licenses: false
cpp:
  vcpkg-allow-git-clone: false
YAML
"$SYFT_BIN" scan dir:/srv/demo-java --config "$SCAN_WORK/syft-config.yaml" \
  --source-name demo-java --source-version demo \
  --override-default-catalogers java-archive-cataloger,java-gradle-lockfile-cataloger \
  -o "cyclonedx-json=$SCAN_WORK/demo-java.syft.json"
"$SCAN_BIN" import --input "$SCAN_WORK/demo-java.syft.json" \
  --name demo-java --output "$SCAN_WORK/demo-java.cdx.json"
```

Fișierul demo-java.cdx.json este exportul local normalizat: îl poți încărca în Active conform pasului 7 sau îl poți folosi mai jos. Păstrează fiecare aplicație/snapshot independent într-o sursă separată. Configurația dezactivează îmbogățirea prin rețea și execuția uneltelor Go; rulează Syft fără root, într-un director ales explicit. Pentru intrări neîncredere, folosește un mediu izolat cu limite de resurse. Nu scana /, directoarele de credențiale sau cache-urile întregii mașini.

```sh
# Optional check: use the credential downloaded in step 8.
"$SCAN_BIN" check --input "$SCAN_WORK/demo-java.cdx.json" \
  --credentials "$SCAN_WORK/credentials.json" --output "$SCAN_WORK/demo-java-check.json"
# Optional source replacement: requires inventory:write and complete input.
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-java.cdx.json" \
  --credentials "$SCAN_WORK/credentials.json" --output "$SCAN_WORK/demo-java-receipt.json"
```

Pentru alte aplicații, schimbă directorul și selecția de catalogere conform documentației Syft. Sunt importate doar cele opt ecosisteme din tabel; identitățile lipsă, versiunile necunoscute sau variantele neacceptate produc codul 3 și inventar parțial, care nu poate înlocui o sursă prin sync. Componentele file sunt excluse intenționat. Clasificatoarele Maven și calificatorii necunoscuți nu sunt eliminați în tăcere. Componentele repetate sunt deduplicate. Awarely nu trimite căile locale, URL-urile sau metadatele arbitrare din SBOM.

Acoperirea completă înseamnă că toate componentele software acceptate din fișierul selectat au fost procesate, nu că producătorul a găsit toate dependențele sau că pachetele sunt instalate. Importul nu autentifică producătorul SBOM-ului. În raport, coverage.unevaluated și precizia fiecărei potriviri explică limitele verificării. Un rezultat fără potriviri pentru un ecosistem neevaluat nu este un rezultat curat.

- [Syft catalogers](https://oss.anchore.com/docs/guides/sbom/catalogers/)
- [CycloneDX Maven](https://cyclonedx.github.io/cyclonedx-maven-plugin/)
- [CycloneDX Gradle](https://github.com/CycloneDX/cyclonedx-gradle-plugin)


<a id="upload"></a>

## 7. Importă SBOM-ul local în Monitor

1. Creează un cont Monitor, acceptă termenii afișați, confirmă codul primit prin email și autentifică-te. Active necesită trial Pro activ sau abonament Pro. Colectarea locală funcționează și fără cont.
2. Deschide Setări → Active. Alege Import din fișier și selectează .cdx.json generat. Dacă este pe server, transferă-l securizat pe stația de lucru. Nu importa fișierul cu credentiale.
3. Alege sau creează aplicația, de exemplu demo-shop. Verifică pachetele, avertismentele de acoperire și previzualizarea modificărilor. Alege înlocuirea doar când fișierul reprezintă scopul dorit al aplicației; adăugarea păstrează intrările existente.
4. Aplică previzualizarea, apoi apasă Salvează în Activele tale. Citirea fișierului se face în browser; Salvează transmite inventarul normalizat către Monitor. Identitățile comune sunt numărate o dată, iar asocierile cu aplicațiile se păstrează.
5. Reîncarcă și verifică numărul de aplicații/componente. Generează verificarea completă și descarcă toate părțile PDF/CSV sau arhivele ZIP. Sursele gestionate prin API își păstrează propriile asocieri; un import manual nu înlocuiește o sursă API.
6. Un backup Monitor restaurează organizația, nu este un import obișnuit de aplicație. Verifică separat scopul mai larg de înlocuire.


<a id="credentials"></a>

## 8. Creează și protejează un token de mașină

1. Folosește un cont de manager al organizației cu acces Pro. Parcurge cerințele MFA afișate în aplicație. Pentru contul cu parolă, activează MFA în Setări → Confidențialitate și autentifică-te cu MFA înainte de administrarea tokenurilor.
2. Deschide Setări → Active → Awarely Scan CLI. Este un token separat pentru mașină, nu cheia API generală CVE din Acces API.
3. Alege Sursă nouă. Completează Nume token / sursă = demo-web-01, Aplicație = demo-shop, Mediu = staging. Alege Doar verificare, Doar sincronizare sau Verificare și sincronizare. Setează o expirare scurtă (1–90 zile; implicit 30).
4. Apasă Creează token, apoi imediat Descarcă configurația secretă. Secretul este disponibil o singură dată și nu poate fi recuperat ulterior. Copiază securizat fișierul descărcat pe Linux, în afara proiectului, la calea de mai jos.
5. Pentru alt server sau proiect întreținut independent creează altă sursă. Dacă folosești aceeași sursă pe servere diferite, fiecare sync înlocuiește snapshot-ul precedent. Aplicația/sursa/mediul sunt fixate de server; --name nu schimbă asocierea.

Transferul se rulează pe calculatorul unde browserul a descărcat fișierul, NU în sesiunea SSH a serverului. În exemplu, schimbă demo-user și demo-host.example.invalid cu utilizatorul și adresa serverului tău. Fișierul ajunge în directorul personal al utilizatorului Linux. Dacă browserul și scannerul sunt pe aceeași mașină, nu ai nevoie de scp; folosește calea fișierului descărcat.

```sh
scp "$HOME/Downloads/awarely-credentials.json" \
  demo-user@demo-host.example.invalid:/home/demo-user/awarely-credentials.json
```

După transfer, revino în terminalul Linux (sesiunea SSH) și rulează comenzile chmod/ls de mai jos. În meniul Credential JSON file introdu calea completă, de exemplu /home/demo-user/awarely-credentials.json. Nu introduce tokenul din fișier.

```sh
chmod 600 "$HOME/awarely-credentials.json"
ls -l "$HOME/awarely-credentials.json"
```

Fișierul trebuie să fie obișnuit, deținut de utilizatorul CLI și fără permisiuni pentru grup/alții. Nu îl include în Git, nu pune tokenul în argumente, loguri sau SBOM. Păstrează adresa API din configurația furnizată de Monitor; nu o înlocui cu adresa site-ului de prezentare.

Doar ilustrație: configurația de mai jos este intenționat invalidă și nu funcționează. Adresa API și toate valorile secrete sunt fictive. Pentru operații reale folosește configurația descărcată.

```json
{
  "schemaVersion": 1,
  "apiUrl": "https://scanner-api.example.invalid",
  "token": "DUMMY_TOKEN_NOT_VALID",
  "applicationId": "DUMMY_APPLICATION_ID",
  "sourceId": "DUMMY_SOURCE_ID"
}
```


<a id="check"></a>

## 9. Verifică fără salvare · alternativă manuală

Folosește un token Doar verificare sau Verificare și sincronizare. Pentru un server, înlocuiește demo-shop.cdx.json cu fișierul din secțiunea distribuției.

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-shop.check.json"
```

Deschide JSON-ul rezultat într-un vizualizator local. summary conține totalurile; matches include identificatorii avizelor, indicii componentelor, versiunile, precizia și dovezile distribuției. coverage arată ce a fost evaluat și ce a rămas neevaluat. Exit 0 înseamnă cerere reușită, chiar dacă există potriviri. Nu schimbă inventarul și nu trimite email. Versiunea nu include o politică automată de eșec CI la vulnerabilități.


<a id="sync"></a>

## 10. Sincronizează o sursă · alternativă manuală

Folosește Doar sincronizare sau Verificare și sincronizare. Snapshot-ul trebuie să fie complet pentru intrările selectate. sync nu execută automat și comanda check.

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-shop.receipt.json"
```

1. Citește confirmarea JSON: status, ID sursă, ID aplicație, revizie și număr de componente ale sursei.
2. Reîncarcă Setări → Active. Sursa este deja salvată; nu trebuie apăsat încă o dată Salvează pentru actualizarea API.
3. Următorul sync înlocuiește sursa respectivă. Celelalte surse și asocierile importurilor manuale rămân. Aceeași identitate/versiune folosită de aplicații este numărată o singură dată; versiunile sau identitățile de distribuție diferite rămân distincte.
4. Rulează verificarea completă din Active pentru raportul web și dovezile descărcabile. Un raport existent este un snapshot; regenerează-l după schimbarea inventarului.


<a id="results"></a>

## 11. Citește rezultatele, exporturile și alertele

1. Confirmat pe versiune înseamnă că versiunea declarată/instalată se încadrează într-un interval comparabil al avizului. Nu dovedește exploatabilitatea în deployment-ul tău. Potrivirile la nivel de produs necesită analiză.
2. Neevaluat înseamnă că serviciul nu a evaluat componenta. Nu înseamnă neafectat. Verifică versiunile lipsă, distribuțiile/furnizorii/canalele neacceptate, pachetele absente din catalog și avertismentul AL2.
3. Pachetele Linux acceptate folosesc avizele oficiale fără limitare la publicarea în ultimele 12 luni. Dependențele aplicațiilor folosesc fereastra declarată de 12 luni. Identificatorii CVE/GHSA diferiți nu sunt garantat reuniți ca aliasuri.
4. În Active, generează verificarea completă. Lista este o previzualizare; PDF și CSV includ toate potrivirile, versiunile și asocierile cu aplicațiile. Descarcă toate părțile. ZIP adaugă JSON, inventarul salvat și manifestul de verificare.
5. Configurează separat canalele, severitățile și programul în Setări → Alerte. Colectarea locală, check, sync și rapoartele la cerere nu trimit emailuri retrospective. Inventarul salvat este folosit de alertele viitoare configurate.
6. Un email filtrat doar Critical și un raport complet generat ulterior pot avea scopuri/momente diferite. Compară sursa, precizia pe versiune, snapshot-ul inventarului și perioada înainte de totaluri.


<a id="after-remediation"></a>

## 12. Scanează din nou după actualizare

Actualizează pachetele prin procesul obișnuit de schimbări al distribuției/aplicației. Verifică versiunea remediată a distribuției și disponibilitatea în depozit; nu o înlocui cu o presupunere despre versiunea upstream. Pe AL2023 verifică release-ul fixat. Ghidul nu îți actualizează automat serverul.

Secvența completă de mai jos necesită permisiuni Verificare și sincronizare. Păstrează doar operațiile dorite; sync schimbă sursa salvată.

```sh
"$SCAN_BIN" host --name demo-web \
  --output "$SCAN_WORK/demo-web-after.cdx.json"
"$SCAN_BIN" check --input "$SCAN_WORK/demo-web-after.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-web-after.check.json"
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-web-after.cdx.json" \
  --credentials "$HOME/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-web-after.receipt.json"
```

Păstrează tokenul aceleiași surse și același scop de colectare. Pentru aplicații repetă app cu --path inițial, în loc de host. Compară potrivirile și acoperirea neevaluată, reîncarcă Active și regenerează raportul. Inventarul nu confirmă că rulează kernelul remediat sau că serviciul a fost repornit.


<a id="credentials-lifecycle"></a>

## 13. Rotește, revocă și retrage o sursă

1. Înainte de expirare, creează un token nou alegând sursa existentă din Active. Descarcă-l o singură dată, protejează-l, verifică operația dorită, apoi revocă tokenul vechi. Nu crea altă sursă doar pentru rotația secretului.
2. Dacă tokenul s-a pierdut sau a fost expus, revocă-l imediat din Active și creează un înlocuitor. Revocarea oprește accesul API; nu șterge inventarul sursei.
3. Golirea deliberată a unei surse necesită un snapshot complet și gol plus opțiunea explicită sync --allow-empty. Nu o folosi pentru a ocoli un rezultat parțial sau o eroare. Nu modifica SBOM-ul ca să pretinzi că este complet.
4. Șterge copiile locale ale credentialelor după revocare când nu mai sunt necesare. Păstrează SBOM-urile și rapoartele conform politicii organizației. Nu există daemon de dezinstalat; poți elimina binarul/directorul descărcat când nu mai este necesar.


<a id="limits"></a>

## 14. Limite și reîncercări

| Limită | Valoare |
| --- | --- |
| Cerere API | 5.000 componente; 2 MiB JSON normalizat |
| Inventar organizație | 5.000 identități unice; 50 aplicații; 2 MiB date normalizate combinate |
| Surse | 50 per organizație |
| Verificare | 6 cereri/minut per organizație și token |
| Sincronizare | 30 cereri/minut per organizație și token; include GET |
| Operații simultane | 2 per organizație și operație |
| Răspuns verificare | 5 MiB; 2.000 identificatori de aviz; 10.000 potriviri de componente |
| Token | 1–90 zile; 100 tokenuri active |
| Rezultat local | 5.000 componente; 5 MiB |

Bugetele scannerului sunt separate de cota lunară a API-ului general CVE. Alte limite ale serviciului pot întoarce 429. CLI-ul nu reîncearcă automat 429 sau conflictul de revizie 409. Respectă Retry-After și distribuie rulările în timp. Rezultatele prea mari sunt refuzate explicit, fără trunchiere. Un catalog vechi/corupt/indisponibil produce eroare, nu raport curat.

Sync citește revizia și folosește o cheie de idempotență. Reîncercările limitate la transport/503 păstrează aceeași cerere. La 409, verifică/recolectează înainte de reîncercare; nu suprascrie orbește altă actualizare. Pentru automatizare controlată există --expected-revision și --idempotency-key. Lipsa confirmării locale după o eroare de rețea/scriere nu dovedește eșecul salvării remote; verifică sursa înainte de repetare. Consultă documentația API pentru contractul complet.


<a id="troubleshooting"></a>

## 15. Probleme uzuale și coduri de ieșire

| Mesaj / situație | Ce faci |
| --- | --- |
| Directory does not exist | Corectează calea la aceeași întrebare; b schimbă tipul scanării. Nu folosi /src dacă aplicația e în /srv. |
| No JAR/WAR/EAR found | Alege directorul cu aplicația Java deja construită. Cere echipei artefactul dacă ai numai codul sursă. |
| Credential file rejected | Verifică numele fișierului și chmod 600; nu lipi tokenul în terminal. Reintrodu calea. |
| ECOSYSTEM_NOT_EVALUATED | Inventarul este disponibil, dar evaluarea CVE pentru acel ecosistem nu este implementată. |
| Synchronization was not confirmed | Verifică inventarul sursei în aplicație înainte de reluare. Fișierul local este păstrat. |

| Simptom | Acțiune |
| --- | --- |
| cosign: command not found / syft: No such file or directory | Pasul 6b: rulează blocul A (Cosign), apoi B (Syft); așteaptă READY la fiecare. Folosește COSIGN_BIN și SYFT_BIN, nu o instalare presupusă în PATH. |
| MISSING / command not found | Revino la pasul 2, instalează utilitarul din blocul distribuției tale și repetă verificarea. |
| gh: unknown command / unknown flag | Actualizează GitHub CLI din depozitul oficial (pasul 2), apoi verifică gh --version și gh attestation verify --help. |
| To get started with GitHub CLI / gh auth login | Ai folosit comenzile vechi, fără --bundle. Nu te autentifica: copiază întregul bloc actualizat de la pasul 3, care descarcă dovada publică și verifică fără cont. |
| release/awarely-scan: No such file or directory / command not found | Instalarea nu s-a încheiat sau ai pierdut variabilele terminalului. Caută prima eroare de la pasul 3, remediază și reia întregul bloc. Nu extrage manual pentru a ocoli atestarea. Dacă instalarea reușise, restabilește SCAN_WORK și SCAN_BIN conform pasului 3. |
| Exit 0 | Operația s-a încheiat; verifică matches și coverage. Nu înseamnă fără vulnerabilități. |
| Exit 2 | Verifică argumentele, formatul, distribuția acceptată, proprietarul/permisiunile credentialelor și accesul la citire. |
| Exit 3 | S-a scris un inventar local parțial. Analizează avertismentele; poți importa/verifica pentru analiză, dar nu sincroniza. |
| Exit 4 | Alege un nume nou într-un director propriu, cu drept de scriere. Fișierele existente sunt păstrate. |
| Exit 5 | Întrerupere sau expirarea duratei. Rezolvă condițiile locale/de rețea înainte de reîncercare. |
| Exit 6 | Operația remote a eșuat. Citește statusul/codul API fără a înregistra credentialele. |
| HTTP 401 / 403 | Token expirat/revocat/invalid, permisiuni greșite sau acces schimbat. Creează tokenul corect din Active. |
| HTTP 409 | Alt sync a schimbat revizia sau cheia de idempotență a fost refolosită cu alt conținut. Verifică inventarul curent. |
| HTTP 413 / 422 | Redu scopul prea mare sau rezolvă snapshot-ul parțial/gol. Nu împărți inventarul prin suprascrieri succesive ale aceleiași surse. |
| HTTP 429 / 503 | Respectă timpul de reîncercare și verifică disponibilitatea. Nu elimina limitele și nu repeta agresiv. |
| Niciun pachet selectat | Verifică numele reale și selectorul. --all-packages este o alternativă explicită, în limite. |
| Alt server a dispărut | Nu partaja aceeași sursă între servere independente. Atribuie fiecăruia propria sursă. |

- [Repository Awarely Scan](https://github.com/awarelyeu/awarely-sbom-scanner)
- [Contract API și limite](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/api.md)
- [Acoperire detaliată](https://github.com/awarelyeu/awarely-sbom-scanner/blob/main/docs/coverage.md)
- [Status serviciu](https://monitor.awarely.ro/status)
