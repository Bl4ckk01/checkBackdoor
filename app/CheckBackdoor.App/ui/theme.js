// Theme chosen by the user, applied before the page is drawn. In a separate file
// (not inside index.html) so the Content-Security-Policy can forbid every inline script.
document.documentElement.className = 'js';
try {
  var t = localStorage.getItem('checkbackdoor-theme');
  if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
} catch (e) {}
