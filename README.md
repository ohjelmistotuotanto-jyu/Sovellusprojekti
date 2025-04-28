# TIES405 Sovellusprojekti (10–15 op)

Sovellusprojektissa opiskelija saa kokemusta työelämän ohjelmistoprojektien suunnittelusta, hallinnasta, läpiviennistä ja raportoinnista, ryhmätyöstä ja tilaajan kanssa toimimisesta sekä projektityössä tarvittavasta kirjallisesta ja suullisesta viestinnästä. Opiskelija saa myös käytännön kokemusta kurssien harjoitustöitä laajempien sovellusten määrittelystä, suunnittelusta, toteuttamisesta ja testaamisesta sekä tarvittavien dokumenttien laatimisesta. Sovellusprojekti edellyttää 250-400 tunnin työmäärää noin neljän kuukauden aikana, joten sille on varattava aikaa vähintään 20-30 tuntia viikossa.

Kurssilta saatavien opintoviikkojen määärä riippuu suoraan tunkikirjanpitoon merkityistä tunneistä. 250-270 tuntia työtä on 10op. Mikäli tunteja on kirjattu tätä enemmän, niin opintopistemäärä saadaan jakamalla tehdyt tunnit luvulla 27 (tulos pyöristetään lähimpään kokonaislukuun).

Kurssin arvosana perustuu itsearviointiin, vertaisarviointiin ja ohjaajien arviointiin.

## Ajankohtaista

- Vaikka kurssin nimi ja kurssikoodi ovat samat, toteutustapa on aikaisempiin vuosiin verrattuna
  - dokumentointia on merkittävästi vähemmän
  - kaikki koodaavat (voitte sisäisesti päättää erilaisia rooleja, esim. scrum master)
  - Kurssia uudistetaan nyt - antakaa palautetta ja kertokaa, miten kurssi kannattaisi teistä toteutttaa. 
- Kurssilla on [discord-kanava](https://discord.gg/ezmrZ8AMGw)
- **Kurssilla kokeilukäytössä jatkuva palautteen keräys**. Anna palautetta kurssikäytännöistä [Norpassa](https://norppa.app.jyu.fi/targets/529/feedback)!
- Kurssi on mahdollista korvata työkokemuksella. Tästä on erillinen [ohje](korvaus.md)

Aikataulu:

* Aloitusluento: 13.1. klo 14:15-16 Ag C523.1 (Agora)
* Välidemo: alustavasti viikolla 10.-14.3.
* Loppudemo: alustavasti viikolla 12.-16.5

Vertaisarviot:

* puolessa välissä ja lopussa vertaisarvio

## Arvosteluperusteet

Arvostelu perustuu seuraaviin asioihin
- Ryhmän sopimien työskentelytapojen noudattaminen
- Ryhmän työskentelytapojen (=prosessin) kehittäminen
- Ryhmätyöskentely
- Tekninen kontribuutio - koodi tai asiantuntijuus
- Valmistautuminen asiakastapaamisiin ja toiminta asiakaspalaverissa
- Työtuntien määrä ja tasaisuus sekä merkintöjen asiallisuus


## Projektin kulku

- Noudatetaan Scrum-henkistä prosessia.
- Kahden viikon välein asiakastapaaminen (Sprint Review), jonka jälkeen Sprint Planning ja Sprint Retrospective.
- Mahdollisuuksien mukaan päivän aluksi Daily Scrum.
- Ensimmäinen viikko ns. nollasprintti, josta lisää alempana.
- Tarkastellaan jatkuvasti prosessin toimivuutta Sprint Retrospectivessä. 
  - Transparency, Inspect & Adapt! 
- Ensimmäisessä asiakastapaamisessa pyritään määrittelemään [Minimum Viable Product](https://en.wikipedia.org/wiki/Minimum_viable_product), koska tarkoituksena on saada ohjelma tuotantoon mahdollisimman nopeasti.
- Suunnitelkaa ajankäyttö ennakkoon ja kirjatkaa toteutunut ajankäyttö erikseen. Voitte itse luoda pohjan, millä seuraatte ajankäytöänne. [Tässä on esimerkki](https://docs.google.com/spreadsheets/d/1bIrpnxBsarBAeqiRuar8L4uPBiIm-7NpyrQh_C0UpZE/edit?gid=1685552279#gid=1685552279) ajankäytön raportoinnista eräästä Helsingin yliopiston sovellusprojektikurssin projektista. 

### Nollasprintti

Perustakaa **heti** jonkinlainen yhteinen TODO-lista. Kirjatkaa sinne nollasprintin tehtävät. Siellä tulisi olla ainakin nämä:
- [ ] Slack, tai vastaava keskustelualusta pystyyn.
  - Ohjaajalle kutsu
- [ ] Product backlogin laatiminen
- [ ] Sprint Task Board / Sprint backlog (fyysinen tai sähköinen)
- [ ] Tuntikirjanpito, josta näkee jokaiseen viikkoon käytetyt tunnit opiskelijoittain
- [ ] Luokaa GitHub-organisaatio ja repository
  - [README standardin mukaiseksi](https://guides.github.com/features/wikis/), lisäksi "päärepoon" linkit muihin repositorioihin, backlogiin sekä sovellukseen.
- [ ] Sopikaa käytettävät teknologiat
  - Huom! Asiakkailla voi olla mielipide käytettävistä teknologioista tai koodauskäytännöistä.
- [ ] CI- ja staging-ympäristö mahdollisimman nopeasti pystyyn
- [ ] Branching-käytännöistä sopiminen
  - Hyvä käytäntö on pitää master-haarassa vain tuotantokelpoista (deployable) koodia. Näin voidaan aina siirtää koodi staging-palvelimelle (ja myöhemmin tuotantoon.)
- [ ] Koodauskäytännöt
  - Sopikaa Definition of Done
  - Pitää olla sellainen, että DoDin kriteerit täyttävä story voitaisiin viedä sellaisenaan tuotantoon!
  - Huom: DoD:ia voi päivittää tiukemmaksi projektin edetessä
- [ ] Valituilla teknologioilla toteutettu "hello world" / [Walking skeleton](http://wiki.c2.com/?WalkingSkeleton) -sovellus staging-ympäristöön. 
  - _"A Walking Skeleton is a tiny implementation of the system that performs a small end-to-end function"_

## Kurssin vaatimuksia

### Projektisuunnitelma

Haastattele asiakasta ja kirjoita mahdollisimman pian projektisuunnitelma, jossa kuvaat kehitettävää sovellusta yleisellä tasolla (projektin README). Millainen valmis projekti vähintään on (MVP)? Toiminnallisuuden tarkempi kuvaaminen kirjoitetaan backlogiin ja tulee varmasti elämään projektin aikana. 

### Backlogit

- **DEEP** Product Backlog pitää olla [DEEP](https://www.romanpichler.com/blog/make-the-product-backlog-deep/).
- **User storyt** Vaatimukset User Story -muodossa. INVEST on tärkeä!
- **Hyväksymiskriteerit** Storylla pitää olla hyväksymiskriteerit (Acceptance critieria), jos se on Product Backlogissa korkealla (=tulee kohta tehtäväksi). Kriteerit kannattaa käydä läpi koko tiimin ja asiakkaan kanssa, vaikka kaikkia ei tarvitse kirjoittaa asiakkaan läsnäollessa. Lue hyvistä käytännöistä alla.
  - lue lisää hyväksymiskriteereistä omasta [ohjeestaan](/ohje-hyv%C3%A4ksymiskriteerit.md)
- **Storyjen seuranta** Seurataan missä sprintissä valmistuneen storyn tekeminen on aloitettu. Tarkoituksena on, että kaikki storyt olisivat valmiita samassa sprintissä kuin ne on aloitettu, mutta metriikoiden optimointi ei saa missään nimessä olla itsetarkoitus — storyn pitää olla aidosti laadukkaasti tehty ja muilta osin valmis ennen kuin se lasketaan tehdyksi.

### Scrum-tapaamiset

- Sprint planning 
- Sprint review
- Retrospektiivi
- Daily

### Koodi

- **Open source**
- **GitHub** Ohjaajan päästävä näkemään lähdekoodi ja commitit

### Deployment environments
  - **Staging-ympäristö** mahdollisimman tuotannon kaltainen.
  - **Tuotantoon!** Tuotos täytyy saada tuotantoon jo projektin aikana, mielellään mahdollisimman nopeasti.
  - **CD** Tuotantoon päivityksen pitää olla [tehokasta ja/tai jatkuvaa](https://puppet.com/blog/continuous-delivery-vs-continuous-deployment-what-s-diff)
  - **Demot stagingista tai tuotannosta** Asiakkaalle demotaan staging- tai tuotantopalvelimelta, ei omalta koneelta.
- **Testaus**
  - Automaatiotestauksen pitää olla riittävän kattava ja hyvin toteutettu
  - Kaikkien yksikkötestien ajaminen on hyvä kestää korkeintaan muutaman minuutin. Korkeamman tason testien, kuten UI-testien ajo saa kestää pidempään, eikä niitä tarvitse ajaa yhtä usein.
  - Erittäin tärkeä konsepti on ns. testipyramidi http://martinfowler.com/bliki/TestPyramid.html. Parin minuutin lukeminen voi säästää kymmeniä tunteja aikaa.
  - Testikoodin laatu tulee mielellän olla yhtä hyvää kuin muunkin koodin.

### Sekalaisia vaatimuksia

- **Tuntikirjapito** Kurssin aikana seurataan tuntimääriä. Työtunneiksi lasketaan myös tapaamiset, esim. tiimin kanssa yhdessä lounastamiset ja itseopiskelu.
  - Kirjaukset oltava kunnossa su 23:59 sekä sprintin vaihtuessa - mielummin päivittäin.
- **Commit esiin** Varmista että committisi näkyvät GitHubissa oikein. Ks. [ohje](https://ohjelmistotuotanto-jyu.github.io/miniprojektin_arvosteluperusteet/#commitit-kadoksissa)
- **Tasaisuus** Ehdottomana vaatimuksena työmäärien tasaisuus viikkotasolla, eli tuntimäärän kuuluu olla viikosta toiseen suunnilleen sama. Sairastumiset yms. neuvoteltava poikkeus. Ilmoita reilusti etukäteen jos tiedät, että osallistumisesi viikon töihin estyy jollain tapaa.
- **Kunnioita** kanssaopiskelijoitasi, kyseessä ei ole yksilökurssi. 
  - Käyttäydy samojen standardien mukaan kuin olisit töissä.
  - Sovittuihin yhteisiin tapaamisiin pitää tulla. Myöhästymisistä, esteistä yms. pitää ilmoittaa ajoissa.
- Siiloutumista tulee välttää. Koodikatselmoinnit!
- **Arvot ja käytännöt**
  - Ryhmän sovittava yhteiset käytännöt ja kirjattava ne (linkki projektin repoon). 
- **Asiakastapaamiset**
  - **Tilavaraukset** Ensimmäisen asiakastapaamisen jälkeen ryhmä on vastuussa asiakastapaamisten järjestämisestä.
  - **Agenda** Asiakastapaamisiin kannattaa luoda melko yksityiskohtainen agenda ja se on hyvä lähettää asiakkaalle ennen varsinaista tapaamista.
  - **Roolit** Kiertävä puheenjohtajan roolit. Lisäksi ainakin kirjuri ja demovastaava. 
  * **Muistiinpanot** Asiakastapaamisista tehtävä muistiinpanot. Keskusteltuja asioita ei saa jättää muistin varaan vaan ne tulee kirjata backlogille.
  - [Vinkkejä asiakaspalaveriin](ohjeita-asiakaspalaveriin.md)
- Retrospektiivit dokumentoitava
  - Teknisenohjaajan oltava paikalla jokaisessa retrospektiivissä. Doodlaus tiimin vastuulla.

## Projektin tavoite

- Ryhmätyötaitojen harjoittelu.
  - Tehtävien ja työn jakaminen
  - Kommunikaatio
  - Organisointi
- Ohjelmistotuotantomenetelmien käytännön harjoittelu.
  - Yhteisen codebasen kanssa työskentely (git)
  - Deployment
- Ketterät toimintatavat
  - Transparency
  - Inspect & Adapt


## Vinkkejä
- Töitä kannattaa tehdä mahdollisimman paljon muiden kanssa fyysisesti samassa tilassa.
- Sprintin aikana on hyvä olla tekeillä ainoastaan 2-3 storya kerrallaan. Tällöin storyt valmistuvat varmemmin. Muutama valmis > melkein kaikki kesken.
- Ohjelmiston arkkitehtuuriin kannattaa käyttää riittävästi huomiota ja jättää sprinttiin aikaa tehdä parannuksia sisäiseen laatuun. Puhdas User Story -hikipaja, jossa keskitytään ainoastaan mahdollisimman nopeaan ominaisuuksien tuottamiseen ei pitkällä tähtäimellä tuota hyviä tuloksia.
- Voi olla hyvä idea hahmotella hyväksymiskriteerit ennen varsinaista asiakastapaamista. Kannattaa kuitenkin jättää hieman pureskeltavaa kriteereihin ennen tapaamista.
- On hyvä käytäntö pitää agenda näkyvillä asiakastapaamisen aikana, jotta keskustelu saadaan pysymään paremmin aiheessa. Käydään kokouskäytäntöjä tarpeen mukaan läpi yhdessä.
- [Vinkkejä asiakaspalaveriin](ohjeita-asiakaspalaveriin.md)
- Eräs hyväksi havaittu sovellus retrojen pitoon on <https://retrotool.io/>

## Roolit

[Rooleista](roolit.md)

## Käytännön ohjeita

- **Tilat:** 
  Kurssilaiset voivat käyttää luokkaa AgC331.3 - tai muuta haluamaansa tilaa. Luokan AgC331.3 käyttäjätunnuksista ja kulkuoikeuksista lähetetään sähköpostia kurssin ensimmäisellä viikolla.

