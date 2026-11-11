---
name: CheckBackdoor
description: Report di verifica offline per Windows; una verifica di integrità completata, letta come la libreria di un launcher di giochi.
colors:
  hue: "#1d5fbf"
  hue-ink: "#ffffff"
  ground: "#f2f4f7"
  surface: "#ffffff"
  raised: "#f6f7f9"
  active: "#e8ebef"
  border: "#e3e6ea"
  rule: "#eceef1"
  control: "#cdd2d8"
  text: "#0b0c0d"
  muted: "#596069"
  neg: "#c4242a"
  warn: "#b45309"
  warn-ink: "#92400e"
  pill-alto-bg: "#ffedea"
  pill-alto: "#831c1e"
  pill-medio-bg: "#fdf0dc"
  pill-medio: "#7c3a06"
  pill-basso-bg: "#eceef1"
  pill-basso: "#3d434a"
  note-bg: "#fffbeb"
  note-line: "#fde68a"
  note-ink: "#92400e"
  dark-hue: "#6f9dff"
  dark-hue-ink: "#0b0c0d"
  dark-ground: "#0c0d0e"
  dark-surface: "#151618"
  dark-raised: "#1c1d20"
  dark-active: "#26282c"
  dark-border: "#282a2e"
  dark-rule: "#1f2124"
  dark-control: "#3b3e43"
  dark-text: "#f0f1f2"
  dark-muted: "#a2a8af"
  dark-neg: "#ff6b6b"
  dark-warn: "#f0a43c"
  dark-warn-ink: "#f5c27a"
  dark-pill-alto-bg: "#3b191b"
  dark-pill-alto: "#ffb4b0"
  dark-pill-medio-bg: "#3a2810"
  dark-pill-medio: "#f5c27a"
  dark-pill-basso-bg: "#24262a"
  dark-pill-basso: "#c9cdd2"
  dark-note-bg: "#241c0c"
  dark-note-line: "#4a3815"
  dark-note-ink: "#f5c27a"
typography:
  display:
    fontFamily: "Segoe UI Variable Display, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "30px"
    fontWeight: 600
    lineHeight: "36px"
    letterSpacing: "-0.015em"
    fontFeature: "tnum"
  headline:
    fontFamily: "Segoe UI Variable Display, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: "30px"
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  title:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: "24px"
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "20px"
    fontFeature: "tnum"
  body-sm:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: "18px"
  label:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
  mono:
    fontFamily: "Cascadia Mono, Cascadia Code, Consolas, SF Mono, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: "18px"
rounded:
  sm: "4px"
  control: "6px"
  sheet: "8px"
  full: "999px"
spacing:
  xxs: "2px"
  xs: "4px"
  sm: "8px"
  gap: "12px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  xxl: "48px"
components:
  button:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-hover:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
  sheet:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.sheet}"
  verify-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.display}"
    rounded: "{rounded.sheet}"
    padding: "24px 24px 20px"
  verification-bar:
    backgroundColor: "{colors.hue}"
    rounded: "{rounded.full}"
    height: "8px"
  severity-cell:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: "12px 16px 14px"
  severity-cell-hover:
    backgroundColor: "{colors.raised}"
  area-item:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "4px 8px"
    height: "44px"
  area-item-selected:
    backgroundColor: "{colors.active}"
    textColor: "{colors.hue}"
  pill-alto:
    backgroundColor: "{colors.pill-alto-bg}"
    textColor: "{colors.pill-alto}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-medio:
    backgroundColor: "{colors.pill-medio-bg}"
    textColor: "{colors.pill-medio}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-basso:
    backgroundColor: "{colors.pill-basso-bg}"
    textColor: "{colors.pill-basso}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-info:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  search-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "32px"
  finding-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    padding: "14px 16px"
  finding-row-hover:
    backgroundColor: "{colors.raised}"
  todo-box:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
  note-warning:
    backgroundColor: "{colors.note-bg}"
    textColor: "{colors.note-ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
---

# Design System: CheckBackdoor

## Overview

**Creative North Star: "La verifica dei file di gioco"**

Il report è una verifica di integrità già conclusa, come quando un launcher controlla i file installati di un gioco: una barra completata, poi la libreria delle aree del PC, ciascuna con il proprio stato. La cornice è un registro acromatico: fondo grigio-azzurro, fogli bianchi con bordi di 1px, inchiostro quasi nero, cifre tabellari. Il colore non decora: una sola tinta blu segna la verifica e la selezione, rosso e ambra compaiono solo dove c'è una gravità da leggere.

La densità è quella di uno strumento di lavoro, non di una landing: testo base a 14px, righe compatte, colonna centrata da 1088px utili. Il verdetto è l'unico testo grande della pagina (30px) e si legge per primo; tutto il resto è lista, filtro e dettaglio espandibile. Il sistema rifiuta il cruscotto di sicurezza di default: niente scudo, niente indicatore circolare del punteggio, niente quattro riquadri KPI colorati.

Il report è un unico file HTML offline: nessuna richiesta esterna all'apertura, quindi il carattere è quello di Windows, l'ambiente in cui lo strumento vive, e le icone sono SVG inline disegnate a mano. Funziona senza JavaScript (filtri nascosti, tutte le segnalazioni visibili) e segue il tema chiaro o scuro del sistema, con un interruttore manuale.

**Key Characteristics:**
- Cornice acromatica a fogli: fondo, fogli bianchi, bordi di 1px, nessuna ombra.
- Una sola tinta (blu verifica) per barra, selezione, focus e stati interattivi.
- Rosso e ambra riservati alla gravità e agli avvisi di controllo incompleto.
- Segoe UI Variable con cifre tabellari; Cascadia Mono per percorsi e hash.
- Icone a tratto singolo da 1.5px, colore ereditato dal testo.
- Due temi completi (chiaro e scuro) con gli stessi ruoli.

## Colors

Un registro acromatico con un solo accento freddo e due colori di gravità, ciascuno con la sua coppia per il tema scuro.

### Primary
- **Blu Verifica** (hue; scuro: dark-hue): il colore della verifica riuscita. Riempie la barra degli elementi superati e il suo pallino in legenda, colora il segno di spunta nel marchio e in "Verifica completata", il nome dell'area selezionata, l'anello di focus, la selezione del testo, il bordo della ricerca attiva e l'hover dei link. Non diventa mai sfondo di superfici o di pulsanti pieni.

### Secondary
- **Rosso Rischio** (neg; scuro: dark-neg): il segmento "a rischio alto" della barra, il conteggio Alto nella striscia di gravità, lo stato "a rischio" nella libreria.
- **Ambra Verifica** (warn per la barra e i pallini; warn-ink per il testo, più scuro per il contrasto AA): elementi "da verificare".
- **Pastiglie di gravità** (pill-alto, pill-medio, pill-basso con i rispettivi sfondi): coppie tinta tenue + inchiostro scuro della stessa famiglia; Info è solo contorno con testo attenuato.

### Tertiary
- **Nota Ambra** (note-bg, note-line, note-ink): solo per l'avviso "Controlli incompleti" e per gli errori di scansione. La variante informativa della nota (confronto con la scansione precedente) torna acromatica: superficie, bordo e testo normali.

### Neutral
- **Fondo Ardesia Chiara** (ground): il piano della pagina e della barra superiore.
- **Foglio** (surface): pannello di verifica, striscia di gravità, lista delle segnalazioni, campi.
- **Foglio Rialzato** (raised): hover di righe e celle, riquadro "Cosa fare", sfondo del codice.
- **Selezione** (active): area selezionata e hover nella libreria, hover del pulsante tema.
- **Bordo** (border) e **Filetto** (rule): il bordo esterno dei fogli e i divisori interni, più tenui.
- **Contorno Controlli** (control): bordo di pulsanti e ricerca, casella di gravità disattivata, barra di scorrimento.
- **Inchiostro** (text) e **Attenuato** (muted): testo principale e metadati, etichette, conteggi secondari.

### Named Rules
**The One Hue Rule.** Il blu appartiene alla verifica e all'interazione: barra, selezione, focus, link in hover. Mai come riempimento di pulsanti, intestazioni o decorazione.

**The Severity-Only Warmth Rule.** Rosso e ambra compaiono solo dove c'è una gravità (pastiglie, conteggi, segmenti della barra, stati delle aree) o un controllo incompleto. Un'area senza problemi resta acromatica: "Verificato" in grigio con la spunta.

**The Paired Theme Rule.** Ogni ruolo ha un valore chiaro e uno scuro (prefisso dark-); il tema scuro è un fondo neutro quasi nero, non blu. Un nuovo colore senza la sua coppia scura non entra nel sistema.

## Typography

**Display Font:** Segoe UI Variable Display (con Segoe UI, system-ui, Helvetica Neue, Arial)
**Body Font:** Segoe UI Variable Text (con Segoe UI, system-ui, Helvetica Neue, Arial)
**Label/Mono Font:** Cascadia Mono (con Cascadia Code, Consolas, SF Mono)

**Character:** Il carattere di Windows stesso, perché il report vive su Windows e non può scaricare font: sobrio, leggibile, con le cifre tabellari attive su tutto il corpo perché i conteggi si confrontano in colonna. Il mono è riservato ai dati grezzi (percorsi, hash, nomi file).

### Hierarchy
- **Display** (600, 30px/36px, -0.015em): solo il verdetto nel pannello di verifica; scende a 24px/30px sotto i 760px.
- **Headline** (600, 24px/30px, -0.01em): il titolo della pagina "Verifica di [PC]" e i numeri della striscia di gravità.
- **Title** (600, 16px/24px): intestazione della lista "Segnalazioni" e dei blocchi della guida finale.
- **Body** (400, 14px/20px): testo corrente; titoli delle segnalazioni a 600, nomi delle aree a 500. Righe lunghe limitate a 70-78ch.
- **Body small** (400, 13px/18px): pulsanti, legenda della barra, coppie chiave-valore, note.
- **Label** (400, 12px/16px): sottotitolo con data e durata, etichette di gravità, metadati delle aree, pastiglie (500), piè di pagina. Mai maiuscolo spaziato.
- **Mono** (400, 12.5px/18px): percorsi, dettagli tecnici, SHA-256, nomi di file nel testo.

### Named Rules
**The Tabular Ledger Rule.** Le cifre sono sempre tabellari (font-variant-numeric: tabular-nums sul body); i numeri sono formattati all'italiana (6.795).

**The One Loud Line Rule.** Il verdetto è l'unica riga in display. Nessun altro titolo raggiunge i 30px.

## Layout

Colonna centrata con larghezza massima 1136px e margini interni di 24px (1088px utili), ripetuta identica nella barra superiore da 48px. Sequenza verticale: titolo con data e azioni, note eventuali, pannello di verifica, striscia di gravità, poi la griglia di lavoro: libreria delle aree da 264px a sinistra (sticky a 16px dall'alto) e lista delle segnalazioni a destra, separate dallo spazio gap di 12px. In fondo la guida in due colonne con 48px di spazio, separata da un filetto.

Ritmo: gap di 12px tra i blocchi principali, 16px dentro le liste, 24px dentro il pannello di verifica e tra blocchi di pagina, 32-48px solo tra la zona di lavoro e la guida.

Responsive: sotto i 1000px la libreria diventa una fila orizzontale scorrevole di schede (min 168px, con bordo e superficie) sopra la lista. Sotto i 760px i margini scendono a 16px, il titolo e le azioni si impilano, la striscia di gravità passa a 2x2, la ricerca occupa tutta la larghezza a 40px di altezza, nelle righe la pastiglia sale sopra il titolo e le coppie chiave-valore diventano una colonna. In stampa spariscono barra, azioni, ricerca e tema e il fondo diventa bianco.

## Elevation & Depth

Il sistema è piatto: nessuna ombra. La profondità è data dal contrasto tonale tra il fondo (ground) e i fogli (surface) e da bordi di 1px; dentro i fogli, i livelli si leggono con filetti più tenui (rule) e con lo sfondo rialzato (raised) per hover e riquadri secondari. Lo stato selezionato usa il tono active, non un'elevazione.

### Named Rules
**The Paper On Slate Rule.** Un contenitore si distingue con superficie + bordo di 1px, mai con un'ombra. Se un elemento sembra dover "galleggiare", va ripensato come foglio o come riga.

## Shapes

Angoli appena morbidi a tre livelli: 8px per i fogli (pannello di verifica, striscia di gravità, lista), 6px per i controlli (pulsanti, ricerca, aree della libreria, note, riquadro "Cosa fare"), 4px per gli elementi minimi (pastiglie, codice inline, anello di focus). La barra di verifica è l'unica forma a capsula (999px), con segmenti separati da 2px di vuoto; i pallini della legenda sono cerchi da 8px. Le icone sono a tratto singolo da 1.5px con estremità arrotondate su griglia 16x16 (12px per l'icona "apri fuori"); il marchio è un cerchio interrotto con una spunta nel blu verifica.

## Components

### Buttons
Discreti e da strumento: servono a scaricare i dati, non a vendere.
- **Shape:** angoli da controllo (6px), altezza 32px, padding orizzontale 12px, icona 16px con 6px di spazio.
- **Default:** foglio con bordo control e testo inchiostro a 13px.
- **Hover / Focus:** sfondo raised e bordo muted (transizione 0.15s); premuto scende di 1px; focus con anello blu da 2px a 2px di distanza.
- **Ghost (pulsante tema):** 32x32px, trasparente, icona attenuata; in hover sfondo active e icona inchiostro. Visibile solo con JavaScript.
- **Link-button:** testo sottolineato a 600 nel colore del testo, blu in hover; usato per "vai all'area" nelle note.

### Chips (pastiglie di gravità)
- **Style:** 22px di altezza, padding 0 8px, angoli 4px, 12px a 500. Alto, Da verificare e Basso con sfondo tenue e inchiostro della stessa famiglia; Info solo contorno.
- **State:** statiche; non sono filtri. I filtri sono le celle della striscia di gravità.

### Cards / Containers
- **Corner Style:** 8px per i fogli.
- **Background:** surface sopra ground.
- **Shadow Strategy:** nessuna (vedi Elevation & Depth).
- **Border:** 1px border all'esterno, 1px rule tra righe e celle.
- **Internal Padding:** 24px nel pannello di verifica, 12-16px in liste e celle.

### Inputs / Fields
- **Style:** campo di ricerca da 32px con icona lente, bordo control, angoli 6px, larghezza massima 360px; placeholder attenuato.
- **Focus:** bordo e contorno di 1px nel blu verifica (bordo doppio visivo, nessun alone).
- **Disabled:** senza JavaScript il campo non viene mostrato.

### Navigation
- **Barra superiore:** 48px sul fondo, filetto inferiore; marchio + "CheckBackdoor" a 600, poi PC e utente attenuati con ellissi, interruttore tema a destra.
- **Libreria delle aree:** lista di pulsanti da almeno 44px con nome (500), metadati a 12px e stato a destra (spunta grigia "Verificato", triangolo rosso "a rischio", cerchio ambra "da verificare", corsivo "Non eseguito"). Selezionata: sfondo active e nome in blu. Su tablet e mobile diventa fila scorrevole di schede.

### Pannello di verifica (signature)
Il verdetto a 30px a sinistra, "Verifica completata in [durata]" con spunta blu a destra, una frase di spiegazione (max 72ch), poi la barra da 8px a tutta larghezza: segmento blu per i superati, ambra e rosso in coda per gli elementi da verificare e a rischio (ogni segmento almeno 4px). La barra si riempie da sinistra in 0.9s con cubic-bezier(.16,1,.3,1), disattivata con prefers-reduced-motion. Sotto, la legenda con pallini e numeri in grassetto.

### Striscia di gravità (signature)
Un unico foglio diviso in quattro celle da filetti verticali; ogni cella è un filtro (aria-pressed) con casella di spunta, etichetta a 12px e numero a 24px (rosso o ambra solo se maggiore di zero). Disattivata: casella vuota, numero attenuato a 400, "· nascoste". Info parte disattivata.

### Riga di segnalazione
Un elemento details: pastiglia (colonna da 72px), titolo a 600 con sottotitolo attenuato su una riga con ellissi, chevron che ruota di 180 gradi in 0.2s. Le righe Alto partono aperte. Il corpo contiene i motivi in elenco, le coppie chiave-valore (etichette da 104px, codice su raised) con link esterni seguiti dall'icona "apri fuori", e il riquadro "Cosa fare." su raised con angoli 6px.

## Do's and Don'ts

### Do:
- **Do** costruire ogni nuovo contenitore come foglio: surface, bordo di 1px, angoli 8px, nessuna ombra.
- **Do** usare il blu verifica solo per verifica riuscita, selezione, focus e hover dei link.
- **Do** dare a ogni colore nuovo la sua coppia per il tema scuro, sia nella preferenza di sistema sia in data-theme.
- **Do** mostrare percorsi, hash e nomi di file in Cascadia Mono a 12.5px, con a capo forzato (overflow-wrap: anywhere).
- **Do** disegnare le icone come SVG inline a tratto singolo da 1.5px su griglia 16x16, colore currentColor.
- **Do** mantenere tutto inline e offline: nessun font, script o immagine esterni.
- **Do** garantire che il report resti completo senza JavaScript: i controlli che dipendono dagli script si nascondono, i contenuti no.

### Don't:
- **Don't** usare scudi, indicatori circolari di punteggio o riquadri KPI colorati: il riepilogo è la barra di verifica e la striscia di gravità.
- **Don't** colorare di rosso o ambra un'area o un numero senza gravità; zero resta inchiostro.
- **Don't** usare il blu come riempimento di pulsanti o superfici.
- **Don't** aggiungere ombre, gradienti o sfocature.
- **Don't** usare etichette in maiuscolo spaziato sopra i titoli: le etichette sono a 12px in grigio, in minuscolo.
- **Don't** usare caratteri o emoji come icone.
