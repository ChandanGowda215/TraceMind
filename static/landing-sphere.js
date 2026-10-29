(() => {
  const canvas = document.querySelector(".hero-sphere");
  const art = canvas?.parentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!canvas || !art) return;

  if (typeof THREE === "undefined") {
    art.classList.add("sphere-unavailable");
    console.error("Trace Mind's interactive sphere could not start because Three.js did not load.");
    return;
  }

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: "high-performance" });
  } catch (error) {
    art.classList.add("sphere-unavailable");
    console.error("Trace Mind's interactive sphere could not create a WebGL renderer.", error);
    return;
  }

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(35, 1, .1, 100);
  camera.position.set(0, 0, 6.2);

  const sphere = new THREE.Group();
  scene.add(sphere);
  scene.add(new THREE.AmbientLight(0x9caaff, .85));

  const keyLight = new THREE.PointLight(0x9278ff, 2.4, 12);
  keyLight.position.set(-2.6, 2.8, 3.8);
  scene.add(keyLight);

  const rimLight = new THREE.PointLight(0x40d8ee, 1.8, 10);
  rimLight.position.set(3.2, -.8, -2.6);
  scene.add(rimLight);

  const core = new THREE.Mesh(
    new THREE.SphereGeometry(1.02, 64, 48),
    new THREE.MeshPhysicalMaterial({
      color: 0x171933,
      metalness: .48,
      roughness: .24,
      clearcoat: 1,
      clearcoatRoughness: .16,
      emissive: 0x211448,
      emissiveIntensity: .35,
    }),
  );
  sphere.add(core);

  const shellGeometry = new THREE.IcosahedronGeometry(1.39, 3);
  const shell = new THREE.LineSegments(
    new THREE.EdgesGeometry(shellGeometry),
    new THREE.LineBasicMaterial({ color: 0x9d8aff, transparent: true, opacity: .21 }),
  );
  sphere.add(shell);

  const particleCount = window.innerWidth < 700 ? 1800 : 3200;
  const particlePositions = new Float32Array(particleCount * 3);
  const particleColors = new Float32Array(particleCount * 3);
  const palette = [new THREE.Color(0x9e8aff), new THREE.Color(0x6adcf1), new THREE.Color(0xdde8ff)];
  for (let index = 0; index < particleCount; index++) {
    const y = Math.random() * 2 - 1;
    const angle = Math.random() * Math.PI * 2;
    const radius = 1.35 + Math.random() * .075;
    const ring = Math.sqrt(1 - y * y);
    particlePositions[index * 3] = Math.cos(angle) * ring * radius;
    particlePositions[index * 3 + 1] = y * radius;
    particlePositions[index * 3 + 2] = Math.sin(angle) * ring * radius;
    const color = palette[Math.random() < .18 ? 0 : Math.random() < .38 ? 1 : 2];
    particleColors[index * 3] = color.r;
    particleColors[index * 3 + 1] = color.g;
    particleColors[index * 3 + 2] = color.b;
  }
  const particleGeometry = new THREE.BufferGeometry();
  particleGeometry.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));
  particleGeometry.setAttribute("color", new THREE.BufferAttribute(particleColors, 3));
  sphere.add(new THREE.Points(
    particleGeometry,
    new THREE.PointsMaterial({
      size: .022,
      vertexColors: true,
      transparent: true,
      opacity: .88,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      sizeAttenuation: true,
    }),
  ));

  const rings = [
    { radius: 1.78, tube: .007, color: 0x927bff, opacity: .55, x: .3, y: .1 },
    { radius: 1.92, tube: .004, color: 0x49d5ee, opacity: .38, x: 1.02, y: -.3 },
    { radius: 1.65, tube: .005, color: 0xd7caff, opacity: .32, x: -.65, y: .8 },
  ];
  rings.forEach(({ radius, tube, color, opacity, x, y }) => {
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(radius, tube, 8, 150),
      new THREE.MeshBasicMaterial({ color, transparent: true, opacity }),
    );
    ring.rotation.set(x, y, .2);
    sphere.add(ring);
  });

  function makeCapability(label, glyph, tint, position) {
    const chip = document.createElement("canvas");
    chip.width = 320;
    chip.height = 112;
    const ctx = chip.getContext("2d");
    if (!ctx) return;
    const radius = 18;
    const gradient = ctx.createLinearGradient(0, 0, 320, 112);
    gradient.addColorStop(0, "rgba(25,27,51,.96)");
    gradient.addColorStop(1, "rgba(12,21,39,.94)");
    ctx.beginPath();
    ctx.roundRect(2, 2, 316, 108, radius);
    ctx.fillStyle = gradient;
    ctx.fill();
    ctx.strokeStyle = `${tint}aa`;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = tint;
    ctx.font = "600 38px 'Segoe UI Symbol', 'Segoe UI', sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(glyph, 52, 56);
    ctx.textAlign = "left";
    ctx.fillStyle = "#f4f1ff";
    ctx.font = "700 20px 'DM Sans', 'Segoe UI', sans-serif";
    ctx.fillText(label, 91, 48);
    ctx.fillStyle = "#aab1ca";
    ctx.font = "500 13px 'DM Mono', Consolas, monospace";
    ctx.fillText("EVIDENCE SIGNAL", 91, 75);

    const texture = new THREE.CanvasTexture(chip);
    texture.colorSpace = THREE.SRGBColorSpace;
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
      map: texture,
      transparent: true,
      depthTest: true,
      depthWrite: false,
    }));
    sprite.position.set(...position);
    sprite.scale.set(.98, .345, 1);
    sphere.add(sprite);
  }

  makeCapability("LOGS", "≋", "#8e79ff", [-.92, .64, .95]);
  makeCapability("METRICS", "▥", "#68def1", [.87, .7, .92]);
  makeCapability("TRACES", "⌁", "#96adff", [1.05, -.13, .78]);
  makeCapability("DEPLOYS", "⬡", "#e4b46e", [-1.03, -.08, .73]);
  makeCapability("ROOT CAUSE", "◎", "#b59aff", [-.79, -.72, .9]);
  makeCapability("REMEDIATION", "✓", "#69e0bb", [.84, -.72, .84]);

  const pointer = { x: 0, y: 0, lastX: null, lastY: null, active: false, targetX: -.08, targetY: .18 };
  function moveSphere(event) {
    if (pointer.lastX !== null && pointer.lastY !== null) {
      pointer.targetY += (event.clientX - pointer.lastX) * .009;
      pointer.targetX += (event.clientY - pointer.lastY) * .009;
      pointer.targetX = THREE.MathUtils.clamp(pointer.targetX, -Math.PI * .48, Math.PI * .48);
    }
    pointer.lastX = event.clientX;
    pointer.lastY = event.clientY;
    pointer.active = true;
  }

  canvas.addEventListener("pointermove", moveSphere, { passive: true });
  canvas.addEventListener("pointerenter", (event) => {
    pointer.lastX = event.clientX;
    pointer.lastY = event.clientY;
    pointer.active = true;
  }, { passive: true });
  canvas.addEventListener("pointerleave", () => {
    pointer.lastX = null;
    pointer.lastY = null;
    pointer.active = false;
  });
  canvas.addEventListener("keydown", (event) => {
    const step = .32;
    if (event.key === "ArrowLeft") pointer.targetY -= step;
    else if (event.key === "ArrowRight") pointer.targetY += step;
    else if (event.key === "ArrowUp") pointer.targetX = THREE.MathUtils.clamp(pointer.targetX - step, -Math.PI * .48, Math.PI * .48);
    else if (event.key === "ArrowDown") pointer.targetX = THREE.MathUtils.clamp(pointer.targetX + step, -Math.PI * .48, Math.PI * .48);
    else return;
    event.preventDefault();
    pointer.active = true;
  });

  const observer = new ResizeObserver(() => {
    const width = Math.max(1, art.clientWidth);
    const height = Math.max(1, art.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.position.z = width < 430 ? 7 : 6.2;
    camera.updateProjectionMatrix();
  });
  observer.observe(art);

  let previousTime = 0;
  let frame = 0;
  function animate(now) {
    frame = requestAnimationFrame(animate);
    const delta = Math.min((now - previousTime) / 1000, .04);
    previousTime = now;
    if (!reducedMotion && !pointer.active) pointer.targetY += delta * .18;
    sphere.rotation.x += (pointer.targetX - sphere.rotation.x) * .075;
    sphere.rotation.y += (pointer.targetY - sphere.rotation.y) * .075;
    shell.rotation.y -= delta * .04;
    keyLight.position.x = -2.6 + Math.sin(now * .00035) * .65;
    renderer.render(scene, camera);
  }
  animate(0);

  window.addEventListener("pagehide", () => {
    cancelAnimationFrame(frame);
    observer.disconnect();
    particleGeometry.dispose();
    shellGeometry.dispose();
    renderer.dispose();
  }, { once: true });
})();
