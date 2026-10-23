// Runs before first paint (blocking, tiny) so the saved theme never flashes.
(function () {
  var saved = null;
  try { saved = window.localStorage.getItem('mtg.theme'); } catch (e) { saved = null; }
  if (saved === 'light' || saved === 'dark') {
    document.documentElement.setAttribute('data-theme', saved);
  }
})();
