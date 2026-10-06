// Applies the saved theme before the first paint, so a dark-mode user never
// sees a white flash. A file rather than inline script, which the console's
// Content-Security-Policy does not allow.
(function () {
  function saved() {
    try {
      return JSON.parse(localStorage.getItem("tbc.prefs") || "{}") || {};
    } catch (e) {
      return {};
    }
  }
  function or(value, fallback) {
    return value || fallback;
  }
  function dark(theme) {
    return theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  }
  var prefs = saved();
  var root = document.documentElement;
  root.dataset.theme = dark(or(prefs.theme, "system")) ? "dark" : "light";
  root.dataset.accent = or(prefs.accent, "iris");
  root.dataset.density = or(prefs.density, "comfortable");
}());
