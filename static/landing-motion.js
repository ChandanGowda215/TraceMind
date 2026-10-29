(() => {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const loader = document.querySelector("#welcome-loader");
  const percent = document.querySelector("#welcome-loader-percent");
  const bar = document.querySelector("#welcome-loader-bar");
  const started = performance.now();
  let progress = 0;

  const progressTimer = window.setInterval(() => {
    progress = Math.min(92, ((performance.now() - started) / 1000) * 92);
    if (percent) percent.textContent = `${Math.floor(progress)}%`;
    if (bar) bar.style.width = `${progress}%`;
  }, 50);

  const pageReady = Promise.all([
    document.fonts?.ready || Promise.resolve(),
    ...Array.from(document.images, (image) => {
      if (image.complete) return Promise.resolve();
      return new Promise((resolve) => {
        image.addEventListener("load", resolve, { once: true });
        image.addEventListener("error", resolve, { once: true });
      });
    }),
  ]);
  const fallback = new Promise((resolve) => window.setTimeout(resolve, 1800));

  const minimumDisplay = new Promise((resolve) => window.setTimeout(resolve, reducedMotion ? 100 : 1100));
  Promise.all([Promise.race([pageReady, fallback]), minimumDisplay]).then(() => {
    window.clearInterval(progressTimer);
    if (percent) percent.textContent = "100%";
    if (bar) bar.style.width = "100%";
    window.setTimeout(() => {
      document.body.classList.add("is-loaded");
      loader?.classList.add("done");
      window.setTimeout(() => loader?.remove(), 450);
    }, reducedMotion ? 0 : 180);
  });

  document.querySelectorAll('a[href="/login"], a[href="/signup"]').forEach((link) => {
    link.addEventListener("click", (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || link.target) return;
      event.preventDefault();
      const overlay = document.createElement("div");
      overlay.className = "page-transition";
      overlay.setAttribute("role", "status");
      overlay.setAttribute("aria-label", "Opening Trace Mind");
      overlay.innerHTML = '<div class="page-transition-mark"><span class="page-transition-dot"></span><span class="page-transition-dot"></span><span class="page-transition-dot"></span><img class="page-transition-core" src="/static/tracemind-logo.png" alt=""></div><div class="page-transition-label">Preparing your workspace</div>';
      document.body.append(overlay);
      window.setTimeout(() => { window.location.href = link.href; }, reducedMotion ? 120 : 720);
    });
  });
})();
