# Awarely Scan: ghid complet pentru Linux și aplicații

De la binarul verificat la un SBOM local, o verificare API sau inventarul salvat. Numele aplicațiilor, căile, identificatorii și credentialele din exemple sunt fictive.

[English](how-to.md) · [Română](how-to.ro.md)

Release: `v0.6.0-alpha.1`

- [1. Alege fluxul](#choose)
- [2. Pregătește mașina Linux](#prerequisites)
- [3. Descarcă, verifică și pornește](#install)
- [4. Debian](#debian)
- [4. Ubuntu](#ubuntu)
- [4. Rocky Linux](#rocky-linux)
- [4. AlmaLinux](#almalinux)
- [4. Amazon Linux 2023](#amazon-linux-2023)
- [4. Amazon Linux 2](#amazon-linux-2)
- [5. Alege ce colectezi](#scope)
- [6. Colectează o aplicație](#applications)
- [6b. Java și alte ecosisteme cu Syft opțional](#syft)
- [7. Importă SBOM-ul local în Monitor](#upload)
- [8. Creează și protejează un token de mașină](#credentials)
- [9. Verifică fără salvare](#check)
- [10. Sincronizează o sursă](#sync)
- [11. Citește rezultatele, exporturile și alertele](#results)
- [12. Scanează din nou după actualizare](#after-remediation)
- [13. Rotește, revocă și retrage o sursă](#credentials-lifecycle)
- [14. Limite și reîncercări](#limits)
- [15. Probleme uzuale și coduri de ieșire](#troubleshooting)

<a id="choose"></a>

## 1. Alege fluxul

| Mod | Cont / plan | Ce se întâmplă |
| --- | --- | --- |
| Fișier local | Fără cont; CLI Apache-2.0 | host/app scrie local JSON CycloneDX 1.6. Fără rețea sau evaluare CVE. |
| Upload în Active | Monitor Pro sau trial Pro activ | Verifici SBOM-ul în browser, aplici modificările și apeși Salvează. |
| Verificare API | Acces Pro + token Doar verificare | Primești un raport JSON local. Nu salvează inventarul și nu trimite alerte. |
| Sincronizare API | Acces Pro + token Doar sincronizare sau ambele | Înlocuiește imediat doar sursa autorizată din inventarul salvat. |

Versiunea este un API preview. Același utilitar, compilat pentru amd64 sau arm64, detectează distribuțiile de mai jos. Integrarea Jenkins, containerele, imaginile AMI/VHD, Alpine și scanarea binarelor arbitrare nu sunt disponibile. Este acceptat un director cu un sistem de fișiere Linux offline; nu un fișier imagine.

Citește întâi pașii 2–3. Alege o distribuție la pasul 4, apoi upload (pasul 7), verificare (pașii 8–9) sau sincronizare (pașii 8 și 10). Pentru manifestele aplicațiilor folosește pasul 6 în locul pasului 4.


<a id="prerequisites"></a>

## 2. Pregătește mașina Linux

1. Folosește contul tău Linux obișnuit. Awarely Scan nu necesită root sau serviciu în fundal. Ai nevoie de citire pentru baza de pachete ori proiectul ales și de scriere în directorul de rezultate.
2. uname -m identifică x86_64 (amd64) sau aarch64 (arm64). Nu distribuim binare pentru alte arhitecturi.
3. Pentru descărcare și verificare ai nevoie de curl, tar, sha256sum și o versiune GitHub CLI cu gh attestation verify. Pregătirea folosește rețeaua; colectarea locală host/app nu.
4. Dacă utilitarele sunt deja instalate, sari peste comenzile de instalare. Altfel alege doar blocul distribuției tale de mai jos. Comenzile instalează utilitare și configurează depozitul oficial GitHub CLI, deci necesită administrator/sudo doar pentru această pregătire, nu pentru scanare.
5. Rulează comenzile următoare în aceeași sesiune de terminal compatibilă Bash. Nu rula Awarely Scan cu sudo. Poți verifica arhiva pe o stație de lucru și o poți transfera securizat pe un server offline.

```sh
uname -m
cat /etc/os-release
command -v curl tar sha256sum gh
gh attestation verify --help
```

Debian 12/13 și Ubuntu 22.04/24.04/26.04 — apt:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl tar coreutils
(
set -eu
GH_KEY_FILE=$(mktemp)
curl --proto '=https' --tlsv1.2 -fL \
  https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  -o "$GH_KEY_FILE"
sudo install -d -m 755 /etc/apt/keyrings
sudo install -m 644 "$GH_KEY_FILE" /etc/apt/keyrings/githubcli-archive-keyring.gpg
rm "$GH_KEY_FILE"
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' "$(dpkg --print-architecture)" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update
sudo apt-get install -y gh
)
```

Rocky Linux 8/9/10, AlmaLinux 8/9/10 și Amazon Linux 2023 — verifică dnf --version. Pentru DNF 4 folosește acest bloc:

```sh
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils 'dnf-command(config-manager)'
sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
sudo dnf install -y gh
```

Doar dacă dnf --version indică DNF 5, folosește alternativa de mai jos în locul blocului DNF 4:

```sh
command -v curl >/dev/null || sudo dnf install -y curl
sudo dnf install -y ca-certificates tar coreutils dnf5-plugins
sudo dnf config-manager addrepo --from-repofile=https://cli.github.com/packages/rpm/gh-cli.repo
sudo dnf install -y gh
```

Amazon Linux 2 — yum (doar inventar/sync; evaluarea CVE rămâne indisponibilă):

```sh
command -v curl >/dev/null || sudo yum install -y curl
sudo yum install -y ca-certificates tar coreutils yum-utils
sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
sudo yum install -y gh
```

Dacă GitHub CLI solicită autentificare pentru descărcarea/verificarea atestărilor publice, rulează gh auth login și urmează pașii în browser. Este autentificare GitHub, separată de Monitor. Nu introduce tokenul Awarely în GitHub. Pentru un server offline, descarcă/verifică pe o stație de încredere și transferă securizat fișierele verificate.

```sh
gh attestation verify --help
```

- [Instalare oficială GitHub CLI pentru Debian, Ubuntu și sisteme RPM](https://github.com/cli/cli/blob/trunk/docs/install_linux.md)


<a id="install"></a>

## 3. Descarcă, verifică și pornește

Comenzile fixează versiunea preview publicată. Oprește-te la orice eroare de descărcare, atestare sau checksum. Lista externă include ambele arhitecturi; verificăm doar arhiva descărcată. Extragerea se face după verificare.

```sh
umask 077
SCAN_WORK=$(mktemp -d "$HOME/awarely-scan.XXXXXXXX")
SCAN_BIN="$SCAN_WORK/release/awarely-scan"
(
set -eu
cd "$SCAN_WORK"
SCAN_VERSION=v0.6.0-alpha.1
case "$(uname -m)" in
  x86_64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac
SCAN_ARCHIVE="awarely-scan_${SCAN_VERSION}_linux_${SCAN_ARCH}.tar.gz"
SCAN_RELEASE="https://github.com/awarelyeu/awarely-sbom-scanner/releases/download/${SCAN_VERSION}"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/$SCAN_ARCHIVE" -o "$SCAN_ARCHIVE"
curl --proto '=https' --tlsv1.2 -fL "$SCAN_RELEASE/SHA256SUMS" -o SHA256SUMS
gh attestation verify "$SCAN_ARCHIVE" \
  --repo awarelyeu/awarely-sbom-scanner \
  --signer-workflow awarelyeu/awarely-sbom-scanner/.github/workflows/release.yml \
  --source-ref "refs/tags/$SCAN_VERSION"
awk -v file="$SCAN_ARCHIVE" '$2 == file { print; found=1 } END { if (!found) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum --check selected-SHA256SUMS
mkdir release
tar -xzf "$SCAN_ARCHIVE" -C release
(cd release && sha256sum --check SHA256SUMS)
"$SCAN_BIN" version
"$SCAN_BIN" help
printf 'Working directory: %s\n' "$SCAN_WORK"
)
```

Păstrează SCAN_WORK și SCAN_BIN pentru pașii următori. Fiecare cale de rezultat trebuie să fie nouă: scannerul nu suprascrie rapoarte. Folosește un director privat nou la următoarea rulare. O versiune viitoare se descarcă și se verifică explicit; nu există actualizare automată.

Dacă deschizi ulterior alt terminal, setează calea reală afișată mai sus: SCAN_WORK=/home/utilizator/awarely-scan.DIRECTORUL_TAU și SCAN_BIN="$SCAN_WORK/release/awarely-scan". Înlocuiește calea exemplu; nu crea altă sursă doar pentru că s-a schimbat sesiunea de terminal.


<a id="debian"></a>

## 4. Debian

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/debian-13-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/debian-13-web-01.receipt.json"
```


<a id="ubuntu"></a>

## 4. Ubuntu

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/ubuntu-24-04-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/ubuntu-24-04-web-01.receipt.json"
```


<a id="rocky-linux"></a>

## 4. Rocky Linux

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/rocky-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/rocky-9-web-01.receipt.json"
```


<a id="almalinux"></a>

## 4. AlmaLinux

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/alma-9-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/alma-9-web-01.receipt.json"
```


<a id="amazon-linux-2023"></a>

## 4. Amazon Linux 2023

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2023-web-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2023-web-01.receipt.json"
```


<a id="amazon-linux-2"></a>

## 4. Amazon Linux 2

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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.check.json"
```

Opțional: sync înlocuiește această sursă în inventarul salvat. Rulează doar dacă acesta este fluxul dorit și tokenul permite operația:

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/al2-legacy-01.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/al2-legacy-01.receipt.json"
```


<a id="scope"></a>

## 5. Alege ce colectezi

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

## 6. Colectează o aplicație

Pe orice gazdă Linux acceptată, alege directorul proiectului cu npm-shrinkwrap.json sau package-lock.json v2/v3. Sunt citite și package.json ca fallback și requirements.txt, însă acestea sunt întotdeauna parțiale. Nu se execută npm install, pip install sau scripturi ale proiectului.

```sh
"$SCAN_BIN" app --path /srv/demo-shop --name demo-shop \
  --output "$SCAN_WORK/demo-shop.cdx.json"
```

Lockfile-urile includ versiunile rezolvate pentru intrările directe/tranzitive, de dezvoltare și opționale; nu dovedesc instalarea sau deployment-ul. Linkurile workspace nu sunt urmărite. requirements.txt păstrează versiunile declarate; nu urmărește include-uri, URL-uri sau rezolvarea dependențelor. Fișierele parțiale pot fi analizate/importate ori verificate, dar sync le refuză. Nu sunt acceptate lockfile-uri pnpm/yarn/poetry sau descoperirea automată a monorepo-urilor.

Pentru colectare extinsă cu Syft, vezi pasul 6b.


<a id="syft"></a>

## 6b. Java și alte ecosisteme cu Syft opțional

Syft este un instrument Anchore separat, Apache-2.0. Awarely nu îl descarcă și nu îl execută automat. Folosește-l pentru colectarea care lipsește din modul nativ, apoi importă fișierul CycloneDX JSON 1.4–1.7. Sunt acceptate și fișiere compatibile produse de pluginurile CycloneDX Maven/Gradle. Importul nu execută build-uri, cod Java sau arhive.

| Ecosistem | Inventar / sync | Verificare CVE |
| --- | --- | --- |
| Java / Maven | Da | Versiuni Maven și coordonate complete |
| npm, Python / PyPI | Da | Intervale comparabile; restul necesită revizuire |
| .NET / NuGet, Go, PHP / Composer, RubyGems, Rust / Cargo | Da | Neevaluat în această versiune |

Pregătire: urmează pașii 2–3 pentru SCAN_WORK și SCAN_BIN. Ai nevoie de curl, tar, sha256sum și Cosign ≥ 2.5 instalat din distribuția oficială Sigstore. Instalarea și verificarea semnăturii necesită internet. Blocul următor fixează Syft 1.54.0 și verifică semnătura și checksum-ul înainte de extracție. Dacă verificarea eșuează, oprește-te; nu o elimina.

- [Cosign installation](https://docs.sigstore.dev/cosign/system_config/installation/)
- [Syft verification](https://oss.anchore.com/docs/installation/verification/)

```sh
(
  set -eu
  SYFT_VERSION=1.54.0
  case "$(uname -m)" in x86_64) SYFT_ARCH=amd64 ;; aarch64|arm64) SYFT_ARCH=arm64 ;; *) exit 2 ;; esac
  SYFT_DIR="$SCAN_WORK/syft-$SYFT_VERSION"
  mkdir -m 700 "$SYFT_DIR"
  cd "$SYFT_DIR"
  BASE="https://github.com/anchore/syft/releases/download/v$SYFT_VERSION"
  ARCHIVE="syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz"
  CHECKSUMS="syft_${SYFT_VERSION}_checksums.txt"
  for FILE in "$ARCHIVE" "$CHECKSUMS" "$CHECKSUMS.sigstore.json"; do
    curl --fail --location --proto '=https' --tlsv1.2 "$BASE/$FILE" -o "$FILE"
  done
  cosign verify-blob "$CHECKSUMS" --bundle "$CHECKSUMS.sigstore.json" \
    --certificate-identity 'https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
  awk -v file="$ARCHIVE" '$2 == file {print}' "$CHECKSUMS" > selected.sha256
  test "$(wc -l < selected.sha256 | tr -d ' ')" = 1
  sha256sum --check selected.sha256
  tar -xzf "$ARCHIVE" syft
  chmod 700 syft
)
SYFT_BIN="$SCAN_WORK/syft-1.54.0/syft"
"$SYFT_BIN" version
```

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

Exemplu de transfer, rulat pe stația unde ai descărcat configurația. Înlocuiește utilizatorul, gazda și directorul fictiv cu gazda ta și calea SCAN_WORK de pe ea. Dacă browserul și CLI-ul rulează pe aceeași mașină, mută direct fișierul descărcat în SCAN_WORK.

```sh
scp ./awarely-credentials.json \
  demo-user@demo-host.example.invalid:/home/demo-user/awarely-scan.REPLACE/awarely-credentials.json
```

```sh
chmod 600 "$SCAN_WORK/awarely-credentials.json"
ls -l "$SCAN_WORK/awarely-credentials.json"
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

## 9. Verifică fără salvare

Folosește un token Doar verificare sau Verificare și sincronizare. Pentru un server, înlocuiește demo-shop.cdx.json cu fișierul din secțiunea distribuției.

```sh
"$SCAN_BIN" check --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-shop.check.json"
```

Deschide JSON-ul rezultat într-un vizualizator local. summary conține totalurile; matches include identificatorii avizelor, indicii componentelor, versiunile, precizia și dovezile distribuției. coverage arată ce a fost evaluat și ce a rămas neevaluat. Exit 0 înseamnă cerere reușită, chiar dacă există potriviri. Nu schimbă inventarul și nu trimite email. Versiunea nu include o politică automată de eșec CI la vulnerabilități.


<a id="sync"></a>

## 10. Sincronizează o sursă

Folosește Doar sincronizare sau Verificare și sincronizare. Snapshot-ul trebuie să fie complet pentru intrările selectate. sync nu execută automat și comanda check.

```sh
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-shop.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
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
  --credentials "$SCAN_WORK/awarely-credentials.json" \
  --output "$SCAN_WORK/demo-web-after.check.json"
"$SCAN_BIN" sync --input "$SCAN_WORK/demo-web-after.cdx.json" \
  --credentials "$SCAN_WORK/awarely-credentials.json" \
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

| Simptom | Acțiune |
| --- | --- |
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
