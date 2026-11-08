/* Runs before the stylesheet so the saved theme is applied on first paint (no light flash). */
try { var t = localStorage.getItem('theme'); if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t; } catch (e) { /* storage unavailable */ }
