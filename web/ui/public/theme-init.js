// Applies the saved (or system) color scheme before the first paint.
try {
  var s = localStorage.getItem("mantine-color-scheme-value");
  if (s !== "light" && s !== "dark") {
    s = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-mantine-color-scheme", s);
} catch (e) {
  /* storage unavailable */
}
