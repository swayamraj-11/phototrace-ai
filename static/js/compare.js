/**
 * PhotoTrace AI — Origin & Sharing Comparator Frontend
 */

document.addEventListener("DOMContentLoaded", () => {
    const compareDropzone = document.getElementById("compareDropzone");
    const multiFileInput = document.getElementById("multiFileInput");
    const selectedFilesList = document.getElementById("selectedFilesList");
    const runCompareBtn = document.getElementById("runCompareBtn");
    const compareResults = document.getElementById("compareResults");
    const compareLoading = document.getElementById("compareLoading");

    let uploadedFiles = [];

    if (!compareDropzone || !multiFileInput) return;

    compareDropzone.addEventListener("click", () => multiFileInput.click());

    ["dragenter", "dragover"].forEach(event => {
        compareDropzone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            compareDropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(event => {
        compareDropzone.addEventListener(event, (e) => {
            e.preventDefault();
            e.stopPropagation();
            compareDropzone.classList.remove("dragover");
        });
    });

    compareDropzone.addEventListener("drop", (e) => {
        const files = Array.from(e.dataTransfer.files);
        addFiles(files);
    });

    multiFileInput.addEventListener("change", (e) => {
        const files = Array.from(multiFileInput.files);
        addFiles(files);
    });

    function addFiles(files) {
        for (const file of files) {
            if (uploadedFiles.length >= 6) {
                showToast("Maximum of 6 files can be compared at once.", "warning");
                break;
            }
            // Check if already added
            if (!uploadedFiles.some(f => f.name === file.name && f.size === file.size)) {
                uploadedFiles.push(file);
            }
        }
        renderSelectedFiles();
    }

    function renderSelectedFiles() {
        if (!selectedFilesList) return;
        selectedFilesList.innerHTML = "";

        if (uploadedFiles.length === 0) {
            runCompareBtn.disabled = true;
            return;
        }

        uploadedFiles.forEach((file, index) => {
            const chip = document.createElement("div");
            chip.className = "telemetry-item";
            chip.style.padding = "0.6rem 0.9rem";
            chip.style.flexDirection = "row";
            chip.style.alignItems = "center";
            chip.style.justifyContent = "space-between";

            const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
            chip.innerHTML = `
                <div style="display:flex;align-items:center;gap:0.6rem;overflow:hidden;">
                    <i class="fa-solid fa-file-image" style="color:var(--accent-cyan);"></i>
                    <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        <span style="font-size:0.85rem;font-weight:600;">Copy #${index + 1}: ${file.name}</span>
                        <div style="font-size:0.75rem;color:var(--text-muted);">${sizeMb} MB</div>
                    </div>
                </div>
                <button type="button" class="btn-cyber-danger btn-sm" style="padding:2px 8px;" data-remove="${index}">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            `;
            selectedFilesList.appendChild(chip);
        });

        // Attach remove handlers
        selectedFilesList.querySelectorAll("[data-remove]").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.getAttribute("data-remove"));
                uploadedFiles.splice(idx, 1);
                renderSelectedFiles();
            });
        });

        runCompareBtn.disabled = uploadedFiles.length < 2;
    }

    if (runCompareBtn) {
        runCompareBtn.addEventListener("click", () => {
            if (uploadedFiles.length < 2) {
                showToast("Please select at least 2 image files to compare.", "warning");
                return;
            }

            compareLoading.style.display = "block";
            compareResults.style.display = "none";

            const formData = new FormData();
            uploadedFiles.forEach(file => {
                formData.append("images", file);
            });

            fetch("/api/compare", {
                method: "POST",
                body: formData
            })
            .then(res => res.json().then(data => ({ status: res.status, ok: res.ok, data })))
            .then(res => {
                compareLoading.style.display = "none";
                if (!res.ok) {
                    showToast(res.data.error || "Comparison failed.", "error");
                    return;
                }

                renderComparison(res.data.comparison);
            })
            .catch(err => {
                compareLoading.style.display = "none";
                showToast("Error processing comparison request.", "error");
            });
        });
    }

    function renderComparison(comp) {
        if (!compareResults) return;
        compareResults.style.display = "block";

        let html = `
            <!-- Forensic Limitations Alert -->
            <div class="cyber-alert cyber-alert-warning" style="margin-bottom:1.5rem;">
                <i class="fa-solid fa-triangle-exclamation" style="font-size:1.2rem;margin-top:2px;"></i>
                <div>
                    <strong>CRITICAL FORENSIC LIMITATION:</strong><br/>
                    ${comp.critical_forensic_disclaimer}
                </div>
            </div>
        `;

        // Earliest supplied copy highlight
        if (comp.earliest_copy) {
            html += `
                <div class="cyber-card" style="border-left:4px solid var(--accent-green);margin-bottom:1.5rem;">
                    <div class="cyber-card-header">
                        <div class="card-title">
                            <i class="fa-solid fa-clock text-green"></i> ${comp.earliest_copy.label}
                        </div>
                        <span class="status-badge status-found">Earliest In Dataset</span>
                    </div>
                    <div style="font-size:0.95rem;margin-bottom:0.75rem;">
                        <strong>Filename:</strong> <span style="color:var(--accent-cyan);font-family:var(--font-mono);">${comp.earliest_copy.filename}</span>
                        &nbsp;&middot;&nbsp; 
                        <strong>Timestamp:</strong> <span style="color:#fff;">${comp.earliest_copy.timestamp}</span>
                    </div>
                    <div style="font-size:0.8rem;color:var(--text-secondary);background:rgba(0,0,0,0.3);padding:0.6rem;border-radius:4px;">
                        <i class="fa-solid fa-info-circle"></i> ${comp.earliest_copy.warning}
                    </div>
                </div>
            `;
        }

        // Identical Files Group
        if (comp.identical_groups && comp.identical_groups.length > 0) {
            html += `
                <div class="cyber-card" style="border-left:4px solid var(--accent-cyan);margin-bottom:1.5rem;">
                    <div class="cyber-card-header">
                        <div class="card-title">
                            <i class="fa-solid fa-equals" style="color:var(--accent-cyan);"></i> Identical Binary Copies (SHA-256 Collisions)
                        </div>
                        <span class="status-badge status-found">Exact Match</span>
                    </div>
            `;
            comp.identical_groups.forEach(grp => {
                html += `
                    <div style="margin-bottom:0.75rem;padding:0.75rem;background:var(--bg-tertiary);border-radius:var(--radius-sm);border:1px solid var(--border-color);">
                        <div style="font-weight:600;font-size:0.85rem;color:var(--accent-green);">
                            <i class="fa-solid fa-fingerprint"></i> SHA-256: <span style="font-family:var(--font-mono);">${grp.sha256}</span>
                        </div>
                        <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.3rem;">
                            Matching Files: <strong>${grp.filenames.join(", ")}</strong>
                        </div>
                        <div style="font-size:0.75rem;color:var(--accent-cyan);margin-top:0.2rem;">
                            ${grp.message}
                        </div>
                    </div>
                `;
            });
            html += `</div>`;
        }

        // Side-by-Side Comparison Table
        html += `
            <div class="cyber-card" style="margin-bottom:1.5rem;">
                <div class="cyber-card-header">
                    <div class="card-title">
                        <i class="fa-solid fa-table-columns"></i> Multi-Copy Comparison Matrix
                    </div>
                </div>
                <div style="overflow-x:auto;">
                    <table class="cyber-table">
                        <thead>
                            <tr>
                                <th>Property</th>
                                ${comp.copies.map(c => `<th>Copy #${c.index}<br/><small style="color:var(--text-muted);font-weight:normal;">${c.filename}</small></th>`).join("")}
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td class="table-field-name">SHA-256 Hash</td>
                                ${comp.copies.map(c => `<td class="table-field-value mono" style="font-size:0.72rem;">${c.sha256.substring(0, 16)}...</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">File Size</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.file_size}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">Raster Dimensions</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.dimensions}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">EXIF Metadata</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.has_exif ? '<span class="status-badge status-found">Intact</span>' : '<span class="status-badge status-na">Stripped</span>'}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">Capture Date</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.capture_timestamp || '<span class="not-available-text">None</span>'}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">Camera Hardware</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.camera_model}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">Software Tag</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.software}</td>`).join("")}
                            </tr>
                            <tr>
                                <td class="table-field-name">GPS Geolocation</td>
                                ${comp.copies.map(c => `<td class="table-field-value">${c.has_gps ? '<span class="status-badge status-found">Present</span>' : '<span class="status-badge status-na">Absent</span>'}</td>`).join("")}
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        // Forensic Evidence Timeline
        html += `
            <div class="cyber-card">
                <div class="cyber-card-header">
                    <div class="card-title">
                        <i class="fa-solid fa-timeline"></i> Evidence Timeline
                    </div>
                </div>
                <div style="display:flex;flex-direction:column;gap:1rem;">
                    ${comp.timeline.map((item, idx) => `
                        <div style="display:flex;gap:1rem;align-items:flex-start;position:relative;">
                            <div style="
                                width: 32px;
                                height: 32px;
                                border-radius: 50%;
                                background: var(--bg-tertiary);
                                border: 2px solid ${item.note.includes('Earliest') ? 'var(--accent-green)' : 'var(--border-highlight)'};
                                display:flex;
                                align-items:center;
                                justify-content:center;
                                font-size:0.85rem;
                                font-weight:bold;
                                color:${item.note.includes('Earliest') ? 'var(--accent-green)' : 'var(--text-secondary)'};
                                flex-shrink:0;
                            ">
                                ${idx + 1}
                            </div>
                            <div style="flex:1;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:var(--radius-sm);padding:0.75rem 1rem;">
                                <div style="display:flex;justify-content:space-between;align-items:center;">
                                    <strong style="color:var(--text-primary);font-size:0.9rem;">${item.filename}</strong>
                                    <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--accent-cyan);">${item.recorded_time}</span>
                                </div>
                                <div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.3rem;">
                                    Resolution: <strong>${item.resolution}</strong> &middot; ${item.exif_status} &middot; Editor: <em>${item.software}</em>
                                </div>
                                <div style="font-size:0.75rem;margin-top:0.3rem;color:${item.note.includes('Earliest') ? 'var(--accent-green)' : 'var(--text-muted)'};font-weight:600;">
                                    &bull; ${item.note}
                                </div>
                            </div>
                        </div>
                    `).join("")}
                </div>
            </div>
        `;

        compareResults.innerHTML = html;
        compareResults.scrollIntoView({ behavior: 'smooth' });
    }
});
