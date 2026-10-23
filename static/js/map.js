/**
 * PhotoTrace AI — Interactive GPS Map Viewer (Leaflet.js)
 */

window.initForensicMap = function(lat, lon, locationTitle = "Photo Evidence Location") {
    const mapElement = document.getElementById("leafletMap");
    if (!mapElement) return;

    if (lat === null || lon === null || isNaN(lat) || isNaN(lon)) {
        mapElement.innerHTML = `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-family:var(--font-mono);gap:0.75rem;">
                <i class="fa-solid fa-location-slash" style="font-size:2rem;color:var(--status-na);"></i>
                <span>GPS coordinates not available in image metadata</span>
            </div>
        `;
        return;
    }

    try {
        // Initialize Leaflet map
        const map = L.map('leafletMap', {
            zoomControl: true,
            scrollWheelZoom: false, // Don't hijack page scrolling
        }).setView([lat, lon], 14);

        // Cyber dark themed CartoDB / OSM tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors'
        }).addTo(map);

        // Custom cyber pulsing pin
        const cyberIcon = L.divIcon({
            className: 'custom-cyber-marker',
            html: `
                <div style="
                    width: 22px; 
                    height: 22px; 
                    background: #00f0ff; 
                    border: 3px solid #060913; 
                    border-radius: 50%; 
                    box-shadow: 0 0 15px #00f0ff;
                "></div>
            `,
            iconSize: [22, 22],
            iconAnchor: [11, 11]
        });

        const marker = L.marker([lat, lon], { icon: cyberIcon }).addTo(map);

        marker.bindPopup(`
            <div style="font-family:'Inter', sans-serif; padding: 4px; color:#111;">
                <strong style="color:#0284c7;"><i class="fa-solid fa-location-dot"></i> ${locationTitle}</strong>
                <div style="font-size:12px; margin-top:4px; font-family:monospace;">
                    Lat: ${lat.toFixed(6)}<br/>Lon: ${lon.toFixed(6)}
                </div>
            </div>
        `).openPopup();

        // Circle radius to indicate GPS accuracy buffer (~35m)
        L.circle([lat, lon], {
            color: '#00f0ff',
            fillColor: '#00f0ff',
            fillOpacity: 0.15,
            radius: 50,
            weight: 1
        }).addTo(map);

        window.forensicMap = map;

        // Force tile redraw when container changes visibility
        setTimeout(() => map.invalidateSize(), 300);

    } catch (err) {
        console.error("Failed to initialize Leaflet GPS map:", err);
    }
};
