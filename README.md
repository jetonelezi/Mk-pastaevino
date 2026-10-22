# AutoParts Tetov

Platformë e thjeshtë për regjistrimin e kompanive të pjesëve të veturave, publikimin e pjesëve dhe kërkimin e tyre.

## Nisja lokale

Kërkohet Node.js 22.13 ose më i ri. Nuk nevojitet instalim paketash.

Në PowerShell, cakto kredencialet e administratorit përpara nisjes së serverit. Fjalëkalimi kërkohet i fshehur dhe ruhet vetëm në mjedisin e procesit:

```powershell
$env:ADMIN_PHONE = "972722060"
$securePassword = Read-Host "Fjalëkalimi admin" -AsSecureString
$env:ADMIN_PASSWORD = (New-Object System.Net.NetworkCredential("", $securePassword)).Password
node server.cjs
```

Hap [http://localhost:3000/](http://localhost:3000/) për të hyrë drejtpërdrejt në katalog, ose shko te [http://localhost:3000/otpadet.html](http://localhost:3000/otpadet.html). Katalogu ndjek rendin markë → model/familje → version, p.sh. BMW → Seria 1 → 116d ose Volkswagen → Golf → Golf 7. Përfshihen markat dhe versionet më të zakonshme në rajon; lista nuk pretendon të jetë regjistër shterues i çdo motori, tregu dhe viti. Kompanitë mund të zgjedhin sugjerimet ose të shkruajnë një model/version që mungon; ato dalin si sugjerim në katalog kur publikohet pjesa. Faqja mbështet shqipen dhe maqedonishten. Paneli i administratorit gjendet te [http://localhost:3000/admin.html](http://localhost:3000/admin.html). Përdor një fjalëkalim unik prej të paktën 12 karakteresh për administratorin. Kredencialet nuk ruhen në kod.

Të dhënat ruhen në `otpadet.sqlite`. Për ta vendosur bazën në një vend tjetër, cakto `OTPADET_DB` përpara nisjes. Sesionet mbyllen kur riniset serveri dhe skadojnë pas 7 ditësh.

### Përdorimi me VS Code Live Server

Lëre `node server.cjs` duke punuar në terminal. Faqet mund të hapen edhe nga Live Server në portin e parazgjedhur `http://localhost:5500`; kërkesat API kalojnë te serveri Node.js në portin `3000`. Për testim më të thjeshtë, përdor direkt adresat në portin `3000`. Pas ndryshimeve në `server.cjs`, rinise serverin Node.js.

Leja për Live Server në portin `5500` është vetëm për zhvillim dhe çaktivizohet kur `NODE_ENV=production`. Nëse Live Server është konfiguruar në port tjetër, përdor portin `3000` ose përditëso allowlist-in e zhvillimit në `server.cjs`.

## Lejet

- Administratori mund të shohë e ndryshojë çdo kompani dhe pjesë, të fshijë kompani të veçanta ose të gjitha kompanitë.
- Administratori mund të caktojë një fjalëkalim të ri për një kompani. Fjalëkalimet ekzistuese nuk mund të shihen, sepse ruhen vetëm si hash; pas rivendosjes, kompania duhet të hyjë përsëri.
- Kompania e identifikuar mund të ndryshojë vetëm profilin dhe pjesët e veta, ose të fshijë llogarinë dhe të gjitha pjesët e veta.
- Serveri verifikon rolin dhe pronësinë për çdo veprim të ndryshimit/fshirjes. Fjalëkalimet ruhen në bazë si hash PBKDF2.

## Publikimi në internet

Përdor vetëm hostim me HTTPS, cakto `NODE_ENV=production`, `ADMIN_PHONE`, `ADMIN_PASSWORD`, `OTPADET_DB` dhe `PUBLIC_ORIGIN` (origjina e saktë publike, pa slash në fund). Mbaje skedarin SQLite jashtë kopjeve publike dhe ruaj kopje rezervë. Për përdorim me më shumë se një proces/server nevojitet një shërbim sesioni i përbashkët në vend të sesioneve në memorie.

Të dhënat e prototipit të vjetër, të ruajtura në `localStorage`, nuk importohen vetvetiu në bazën e re. Fut regjistrimet sërish përmes faqes ose importoji veçmas në bazën e serverit.
