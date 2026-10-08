# Jenkins: de la instalare la prima verificare

Acest ghid descrie integrarea aflată în dezvoltare. În producție folosește doar un release publicat și verificat al pluginului.

## 1. Pregătește Jenkins o singură dată

Ai nevoie de Jenkins 2.580.1 sau mai nou, un Java compatibil cu versiunea Jenkins (testăm cu JDK 21) și un agent Linux amd64 sau arm64 care rulează fără root. Controllerul trebuie să aibă zero executori. Build-ul aplicației poate necesita Node.js/npm, Python ori Maven/Java; scannerul citește fișiere deja existente și nu instalează aceste runtime-uri.

Descarcă HPI-ul din [release-urile pluginului](https://github.com/awarelyeu/awarely-sbom-scanner/releases) și urmează [verificarea provenienței și checksum-ului](releases.md). Un plugin poate executa cod pe controller.

În **Manage Jenkins → Plugins → Available plugins**, instalează sau actualizează dependențele: **Credentials**, **Plain Credentials**, **Branch API**, **SCM API**, **Structs**, **Jackson 2 API** și **Commons Compress API**. Jenkins rezolvă și dependențele lor. Pentru Jenkinsfile, instalează și **Pipeline**. Verifică avertismentele de securitate din **Manage Jenkins**.

Apoi deschide **Plugins → Advanced settings → Deploy Plugin**, selectează HPI-ul verificat și încarcă-l. Repornește Jenkins după terminarea build-urilor. Confirmă că **Awarely Scan** apare în **Installed plugins**, fără eroare de încărcare. HPI-ul se distribuie aici; pluginul nu este încă listat în Jenkins Update Center.

În **Manage Jenkins → System → Awarely Scan**, administratorul configurează:

1. **Allow verified tool downloads**, dacă agenții pot descărca CLI-ul și Syft la versiunile fixate. Această opțiune nu rulează automat orice versiune `latest`.
2. Numele complete ale joburilor care pot contacta Monitor, câte unul pe linie. Include numele folderului și ramurii pentru joburile multibranch. Nu se acceptă wildcard-uri.
3. Numele exacte ale agenților dedicați build-urilor de încredere. Separă-i de joburile și PR-urile externe.
4. Originea HTTPS din fișierul de credențiale descărcat din propriul cont Monitor, la **Allowed Monitor API origins**. Aceasta conține protocolul, hostname-ul și eventual portul, fără cale.
5. La **Jobs allowed to synchronize inventory**, aprobă separat joburile de deployment care pot modifica inventarul. Aprobarea pentru check nu permite automat sync.
6. Separat, joburile care pot inventaria sistemul Linux al agentului, la **Jobs allowed to inventory the agent host**.

O scanare locală de aplicație nu necesită cont sau credențiale Monitor. Cache-ul se află în `.awarely-scan` sub directorul agentului, în afara workspace-ului, cu permisiuni doar pentru proprietar. Pentru utilizare fără descărcări, administratorul pregătește arhiva CLI fixată și cache-ul Syft verificat în avans. O arhivă absentă sau modificată oprește pasul.

## 2. Adaugă credențialele pentru verificare

În Monitor, deschide **Setări → Active → Awarely Scan CLI**. Cu acces Pro și MFA, creează o credențială **Check only**, cu expirare, pentru aplicația și sursa dorite. Descarcă fișierul JSON.

În credentials store-ul folderului Jenkins potrivit, adaugă un **Secret file**, încarcă JSON-ul și alege un ID clar, de exemplu `awarely-monitor-check`. Limitează drepturile de configurare a joburilor și accesul la credențiale. Nu pune JSON-ul în Git, tokenul în Jenkinsfile sau credențiala într-o variabilă de mediu.

Pluginul citește Secret file numai pentru operațiunea API și îl transmite CLI-ului verificat prin standard input. Nu îl copiază în workspace și nu îl arhivează.

## 3. Prima scanare locală

Într-un proiect Freestyle, alege **Add build step → Awarely Scan: inventory, check or synchronize**. Selectează tipul aplicației, o cale relativă la workspace, eticheta inventarului și **Save local inventory only**. Dacă folosești Syft, construiește aplicația înainte de scanare.

În Pipeline poți folosi **Pipeline Syntax → Snippet Generator** sau exemplul:

```groovy
pipeline {
  agent { label 'linux' }
  options {
    timeout(time: 15, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '20'))
    skipStagesAfterUnstable()
  }
  stages {
    stage('Inventory') {
      steps {
        awarelyScan collector: 'npm', mode: 'local',
          path: '.', applicationLabel: 'shop'
      }
    }
  }
}
```

Workspace-ul trebuie să conțină lockfile-ul aplicației. Înlocuiește exemplele cu propriile nume și căi. Pentru citirea nativă a lockfile-ului nu trebuie să rulezi `npm install`. Syft citește dependențele instalate și artefactele construite, deci pregătește-le într-un pas de build anterior.

După build, deschide **Awarely Scan** și **Artifacts**. Inventarul apare la `awarely/<run-id>/inventory.cdx.json`. Artefactele descriu software-ul tău; limitează accesul la ele și perioada de păstrare.

## 4. Verificarea CVE și politica build-ului

Înlocuiește pasul cu:

```groovy
awarelyScan collector: 'npm', mode: 'check',
  path: '.', applicationLabel: 'shop',
  credentialsId: 'awarely-monitor-check',
  severityThreshold: 'HIGH', failOnIncomplete: true
```

`check` trimite identitățile normalizate ale pachetelor, versiunile și dovezile către API-ul Monitor configurat. Nu salvează inventarul și nu schimbă alertele. Jenkins păstrează raportul JSON complet și afișează un rezumat cu perioada, severitatea, precizia și componentele neevaluate.

- `REPORT_ONLY` afișează rezultatele fără prag de severitate.
- `CRITICAL`, `HIGH`, `MEDIUM` sau `LOW` marchează build-ul **UNSTABLE** dacă există o potrivire confirmată pe versiune la acel nivel sau mai sus.
- Potrivirile numai pe produs rămân vizibile, dar nu declanșează pragul pentru versiuni confirmate.
- `failOnIncomplete: true` marchează separat **UNSTABLE** pentru inventar parțial sau componente neevaluate, inclusiv când nu există potriviri CVE.
- Erorile de intrare, autentificare, API ori verificare a uneltelor opresc pasul; nu sunt transformate în rezultate cu zero CVE.

În Declarative Pipeline, `skipStagesAfterUnstable()` împiedică etapele ulterioare, inclusiv deployment-ul, după un astfel de rezultat. `REPORT_ONLY` nu dezactivează politica separată pentru acoperire incompletă. Nicio potrivire nu înseamnă automat că aplicația este sigură.

## 5. Python, Java și celelalte tipuri de inventar

Pentru un virtual environment creat în directorul aplicației:

```groovy
awarelyScan collector: 'python-syft', mode: 'check',
  path: 'services/reports', applicationLabel: 'reports',
  credentialsId: 'awarely-monitor-check', severityThreshold: 'HIGH'
```

Creează mediul și instalează dependențele înainte, prin pașii obișnuiți ai proiectului. Varianta `python` citește requirements.txt și raportează inventar parțial, fiindcă nu cunoaște toate dependențele instalate.

Pentru Java:

```groovy
awarelyScan collector: 'java', mode: 'check',
  path: 'services/shipping', applicationLabel: 'shipping',
  credentialsId: 'awarely-monitor-check', severityThreshold: 'HIGH'
```

Construiește JAR/WAR/EAR și pregătește dependențele înainte de scanare. Un director numai cu surse nu reprezintă neapărat aplicația construită. Syft urmează versiunea CLI fixată de plugin; nu există întrebări interactive sau o setare pentru executarea oricărei versiuni Syft.

Alte variante:

| `collector` | Ce selectezi |
| --- | --- |
| `npm-syft` | Directorul aplicației Node.js cu dependențele instalate |
| `linux` | Pachetele sistemului Linux al agentului; `allPackages: true` extinde inventarul |
| `other` | Fișiere NuGet, Go, Composer, RubyGems sau Cargo; evaluarea CVE este încă neevaluată |
| `import` | Fișier CycloneDX extern cu pachetele aplicației |
| `existing` | Un inventar Awarely existent, fără repetarea scanării |

Scanarea Linux descrie **agentul Jenkins**. Nu scanează automat serverul de producție sau imaginea unui container.

## 6. Sincronizarea inventarului implementat

Folosește o credențială separată **Sync only** și un job de deployment de încredere. Fiecare sursă aplicație/mediu trebuie să aibă un singur job care o actualizează. Sincronizează inventarul artefactului implementat după deployment-ul reușit; un simplu build ar trebui, de regulă, să folosească `check`.

```groovy
awarelyScan collector: 'java', mode: 'sync',
  path: 'services/shipping', applicationLabel: 'shipping-production',
  credentialsId: 'awarely-monitor-sync'
```

Eticheta descrie SBOM-ul; credențiala stabilește aplicația și sursa destinație. Sync înlocuiește imediat numai acea sursă și le păstrează pe celelalte. Inventarele parțiale sau goale sunt refuzate. Pluginul serializează sincronizările sale, persistă ordinea build-urilor și refuză un build mai vechi ori alt job care încearcă să scrie aceeași sursă. Serverul verifică separat revizia și cheia de idempotency.

Nu pune sync într-un `retry` automat. După timeout, restart de controller sau pierderea răspunsului, verifică sursa în Monitor înainte de repetare. CLI-ul păstrează aceeași revizie și cheie pentru propriile retry-uri de transport, limitate. Pluginul nu reia automat un proces întrerupt de restart-ul controllerului.

## 7. Rezolvarea problemelor și actualizările

| Mesaj/situație | Ce faci |
| --- | --- |
| Director absent | Corectează calea relativă la workspace și verifică checkout-ul/build-ul. Căile absolute și `..` sunt refuzate. |
| Unealtă absentă | Administratorul permite descărcarea verificată sau pregătește cache-ul versiunii fixate. |
| Job, agent sau destinație neaprobate | Administratorul aprobă configurația de încredere dorită. |
| Inventar Python parțial | Folosește `python-syft` după instalarea dependențelor în virtual environment. |
| Ecosistem neevaluat | Componenta există în inventar, dar serviciul nu îi evaluează încă CVE-urile. |
| Alt job/build mai nou deține sursa | Folosește jobul desemnat. După redenumirea jobului ori resetarea numerotării, administratorul trebuie să revizuiască legătura persistentă. |
| Sync întrerupt | Verifică inventarul salvat în Monitor înainte de repetare. |

Actualizează deliberat pluginul dintr-un release verificat și testează întâi pe staging. Versiunile și digesturile CLI sunt fixate de release-ul pluginului, iar Syft urmează CLI-ul. Build-urile obișnuite nu rulează `update`, installere sau `latest`.

Rotește/revocă credențialele când se schimbă joburile ori permisiunile. Păstrează numai artefactele necesare. Dacă un build întrerupt nu își poate șterge fișierele private, curăță sau recreează agentul izolat înainte de reutilizare.

Verificările respectă limita API a contului Monitor (în prezent șase verificări pe minut, cu un număr limitat de operații simultane). Decalează joburile paralele; nu crea credențiale suplimentare pentru a ocoli limita contului. O cerere refuzată produce o eroare vizibilă și păstrează SBOM-ul local.
