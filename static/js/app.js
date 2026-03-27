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
const titleRoot = document.getElementById("pipelineTitle");
const loaderBar = document.getElementById("pipelineLoaderBar");

function typeText(target, text, speed = 16, onDone) {
  target.textContent = "";
  let idx = 0;
  const timer = setInterval(() => {
    target.textContent += text[idx];
    idx += 1;
    if (idx >= text.length) {
      clearInterval(timer);
      if (typeof onDone === "function") onDone();
    }
  }, speed);
}

function openModal() {
  modal.classList.remove("hidden");
  requestAnimationFrame(() => modal.classList.add("open"));
  modal.setAttribute("aria-hidden", "false");
}

function closeModalAnimated() {
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
  setTimeout(() => modal.classList.add("hidden"), 320);
}

function runPipeline({ fileName, hash, fermat, mode = "encrypt", onDone, autoClose = false }) {
  if (!modal || !stepsRoot || !textRoot) return;
  const reverse = mode === "decrypt";
  if (titleRoot) {
    titleRoot.textContent = reverse ? "Decryption Pipeline" : "Encryption Pipeline";
  }
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

  if (loaderBar) {
    loaderBar.classList.remove("complete");
    loaderBar.classList.add("running");
  }
  openModal();
  typeText(textRoot, longText, 12, () => {
    if (loaderBar) {
      loaderBar.classList.remove("running");
      loaderBar.classList.add("complete");
    }
    const finish = () => {
      if (autoClose) {
        closeModalAnimated();
      }
      if (typeof onDone === "function") {
        onDone();
      }
    };
    setTimeout(finish, 700);
  });
}

window.showPipeline = function (button, reverse = false) {
  runPipeline({
    fileName: button.dataset.file || "file",
    hash: button.dataset.hash || "",
    fermat: button.dataset.fermat || "N/A",
    mode: reverse ? "decrypt" : "encrypt",
    autoClose: false,
  });
};

if (closeModal) {
  closeModal.addEventListener("click", () => {
    closeModalAnimated();
  });
}

document.querySelectorAll(".secure-action").forEach((button) => {
  button.addEventListener("click", () => {
    const url = button.dataset.url;
    runPipeline({
      fileName: button.dataset.file || "file",
      hash: button.dataset.hash || "",
      fermat: button.dataset.fermat || "N/A",
      mode: button.dataset.mode || "decrypt",
      autoClose: true,
      onDone: () => {
        if (url) window.location.href = url;
      },
    });
  });
});

const uploadMeta = document.getElementById("uploadPopupMeta");
if (uploadMeta) {
  const fileId = uploadMeta.dataset.fileId;
  const lockButton = document.querySelector(`[data-file-id='${fileId}']`);
  if (lockButton) {
    runPipeline({
      fileName: lockButton.dataset.file || "file",
      hash: lockButton.dataset.hash || "",
      fermat: lockButton.dataset.fermat || "N/A",
      mode: "encrypt",
      autoClose: true,
      onDone: () => {
        const url = new URL(window.location.href);
        url.searchParams.delete("enc");
        url.searchParams.delete("file_id");
        window.history.replaceState({}, "", url.toString());
      },
    });
  }
}
