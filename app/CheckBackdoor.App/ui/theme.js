// Tema scelto dall'utente, applicato prima che la pagina venga disegnata. In un file a parte
// (e non dentro index.html) cosi' la Content-Security-Policy puo' vietare ogni script in linea.
document.documentElement.className = 'js';
try {
  var t = localStorage.getItem('checkbackdoor-theme');
  if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
} catch (e) {}
