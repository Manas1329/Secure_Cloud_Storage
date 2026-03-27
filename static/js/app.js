const themeToggle = document.getElementById("themeToggle");
const html = document.documentElement;

if (themeToggle) {
  const savedTheme = localStorage.getItem("securecloud-theme");
  if (savedTheme) html.setAttribute("data-theme", savedTheme);
  themeToggle.addEventListener("click", () => {
    const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    localStorage.setItem("securecloud-theme", next);
  });
}

const dropZone = document.getElementById("dropZone");
const uploadForm = document.getElementById("uploadForm");
if (dropZone && uploadForm) {
  const fileInput = uploadForm.querySelector("input[type='file']");
  ["dragenter", "dragover"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add("active");
    });
  });
  ["dragleave", "drop"].forEach((evt) => {
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove("active");
    });
  });
  dropZone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (!file || !fileInput) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInput.files = transfer.files;
    dropZone.textContent = `Selected: ${file.name}`;
  });
}

const modal = document.getElementById("pipelineModal");
const closeModal = document.getElementById("closeModal");
const stepsRoot = document.getElementById("pipelineSteps");
const textRoot = document.getElementById("pipelineText");

function typeText(target, text, speed = 16) {
  target.textContent = "";
  let idx = 0;
  const timer = setInterval(() => {
    target.textContent += text[idx];
    idx += 1;
    if (idx >= text.length) clearInterval(timer);
  }, speed);
}

window.showPipeline = function (button, reverse = false) {
  if (!modal || !stepsRoot || !textRoot) return;
  const hash = button.dataset.hash || "";
  const fermat = button.dataset.fermat || "N/A";
  const fileName = button.dataset.file || "file";
  const steps = reverse
    ? ["Fetch Encrypted File", "Regenerate Key", "AES Decryption", "SHA-256 Verify", "Serve File"]
    : ["Upload", "SHA-256", "Fermat Key Logic", "AES Encryption", "Store Metadata"];

  stepsRoot.innerHTML = "";
  steps.forEach((step, i) => {
    const el = document.createElement("span");
    el.style.animationDelay = `${i * 130}ms`;
    el.textContent = step;
    stepsRoot.appendChild(el);
  });

  const longText = reverse
    ? `File: ${fileName}\nRecompute key seed using Fermat validation:\n${fermat}\nDecrypt using AES-GCM nonce+tag\nRecomputed SHA-256: ${hash.slice(0, 24)}...\nIntegrity check passed.`
    : `File: ${fileName}\nGenerating SHA-256 digest...\nSHA-256: ${hash}\nFermat validation:\n${fermat}\nDeriving key and encrypting with AES-GCM...\nEncrypted file committed to storage.`;

  typeText(textRoot, longText, 12);
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
};

if (closeModal) {
  closeModal.addEventListener("click", () => {
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
  });
}
