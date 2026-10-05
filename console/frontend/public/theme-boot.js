// Applies the saved theme before the first paint, so a dark-mode user never
// sees a white flash. A file rather than inline script, which the console's
// Content-Security-Policy does not allow.
(function () {
  try {
    var prefs = JSON.parse(localStorage.getItem('tbc.prefs') || '{}');
    var theme = prefs.theme || 'system';
    var dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
    var root = document.documentElement;
    root.dataset.theme = dark ? 'dark' : 'light';
    root.dataset.accent = prefs.accent || 'iris';
    root.dataset.density = prefs.density || 'comfortable';
  } catch (e) {
    document.documentElement.dataset.theme = 'light';
  }
})();
