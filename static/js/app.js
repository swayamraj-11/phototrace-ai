/**
 * PhotoTrace AI — Main Frontend Application Logic
 */

// Toast notification helper
function showToast(message, type = "info") {
    const area = document.getElementById("notificationArea");
    if (!area) return;

    const toast = document.createElement("div");
    toast.className = `toast-msg ${type}`;
    
    let icon = "fa-circle-info";
    if (type === "success") icon = "fa-circle-check";
    if (type === "error") icon = "fa-triangle-exclamation";

    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    area.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(40px)";
        toast.style.transition = "all 0.3s ease";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Copy to clipboard helper
function copyToClipboard(text, btnElement) {
    if (!navigator.clipboard) {
        // Fallback for older browsers
        const textarea = document.createElement("textarea");
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
    } else {
        navigator.clipboard.writeText(text);
    }

    if (btnElement) {
        const origHtml = btnElement.innerHTML;
        btnElement.innerHTML = `<i class="fa-solid fa-check text-green"></i> Copied!`;
        setTimeout(() => {
            btnElement.innerHTML = origHtml;
        }, 2000);
    }
    showToast("Copied to clipboard!", "success");
}

// Tab Switching
function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            const parent = btn.closest(".cyber-tabs-container") || document;

            parent.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            parent.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add("active");
                // Trigger map invalidateSize if map tab opened
                if (targetId === "tab-gps" && window.forensicMap) {
                    setTimeout(() => window.forensicMap.invalidateSize(), 100);
                }
            }
        });
    });
}

// Drag & Drop File Upload Handler
function initUploadWorkspace() {
    const dropzone = document.getElementById("uploadDropzone");
    const fileInput = document.getElementById("evidenceFileInput");
    const scanOverlay = document.getElementById("scanningOverlay");
    const scanStatusText = document.getElementById("scanStatusText");

    if (!dropzone || !fileInput) return;

    // Click to open file picker
    dropzone.addEventListener("click", () => fileInput.click());

    // Drag-over styling
    ["dragenter", "dragover"].forEach(event => {
        dropzone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(event => {
        dropzone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    // Handle Drop
    dropzone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            handleSingleUpload(files[0]);
        }
    });

    // Handle File Input Change
    fileInput.addEventListener("change", (e) => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleSingleUpload(fileInput.files[0]);
        }
    });

    function handleSingleUpload(file) {
        // Client-side format pre-check
        const allowed = [".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp"];
        const lowerName = file.name.toLowerCase();
        const isValidExt = allowed.some(ext => lowerName.endsWith(ext));
        
        if (!isValidExt) {
            showToast("Unsupported file format. Please upload JPEG, PNG, TIFF, or WebP.", "error");
            return;
        }

        // 32MB limit check
        if (file.size > 32 * 1024 * 1024) {
            showToast("File size exceeds 32MB server threshold.", "error");
            return;
        }

        // Show scanner overlay
        if (scanOverlay) {
            scanOverlay.style.display = "flex";
            const statuses = [
                "Acquiring file stream & verifying magic bytes...",
                "Calculating SHA-256 cryptographic digest...",
                "Parsing EXIF metadata & GPS telemetry tags...",
                "Executing rule-based forensic integrity checks...",
                "Rendering Error Level Analysis (ELA) map..."
            ];
            let step = 0;
            const timer = setInterval(() => {
                step = (step + 1) % statuses.length;
                if (scanStatusText) scanStatusText.textContent = statuses[step];
            }, 500);

            const formData = new FormData();
            formData.append("image", file);

            fetch("/api/analyze", {
                method: "POST",
                body: formData
            })
            .then(res => res.json().then(data => ({ status: res.status, ok: res.ok, data })))
            .then(response => {
                clearInterval(timer);
                if (!response.ok) {
                    scanOverlay.style.display = "none";
                    showToast(response.data.error || "Analysis failed.", "error");
                    return;
                }
                
                showToast("Forensic extraction complete!", "success");
                // Redirect to the dedicated analysis view
                window.location.href = `/analysis/${response.data.analysis_id}`;
            })
            .catch(err => {
                clearInterval(timer);
                scanOverlay.style.display = "none";
                showToast("Network error during analysis upload.", "error");
            });
        }
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initUploadWorkspace();
});
