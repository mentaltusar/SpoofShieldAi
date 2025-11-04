

function drawGauge(containerId, value){
  // simple SVG semicircular gauge
  const cont = document.getElementById(containerId);
  if(!cont) return;
  const percent = Math.max(0, Math.min(100, value));
  cont.innerHTML = '';
  const svgNS = "http://www.w3.org/2000/svg";
  const w = 300, h = 160;
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("width", w);
  svg.setAttribute("height", h);
  // background arc
  const arc = document.createElementNS(svgNS, "path");
  const r = 120;
  const cx = w/2, cy = h;
  // describe semicircle path
  const startX = cx - r, startY = cy;
  const endX = cx + r, endY = cy;
  arc.setAttribute("d", `M ${startX} ${startY} A ${r} ${r} 0 0 1 ${endX} ${endY}`);
  arc.setAttribute("stroke", "#1f2d3a");
  arc.setAttribute("stroke-width", "18");
  arc.setAttribute("fill", "none");
  svg.appendChild(arc);

  // colored arc overlay based on percent
  const angle = Math.PI * (percent/100);
  const sx = cx - r;
  const ex = cx - r * Math.cos(angle) + r * Math.sin(0); // simpler compute below
  // draw using stroke-dasharray trick
  const overlay = document.createElementNS(svgNS, "path");
  overlay.setAttribute("d", arc.getAttribute("d"));
  overlay.setAttribute("stroke-linecap","round");
  overlay.setAttribute("stroke-width","18");
  overlay.setAttribute("fill","none");
  overlay.setAttribute("stroke","url(#g)");
  overlay.setAttribute("style","transform-origin:center;transform:rotate(180deg)");
  // gradient defs
  const defs = document.createElementNS(svgNS, "defs");
  defs.innerHTML = `<linearGradient id="g" x1="0" x2="1"><stop offset="0%" stop-color="#00ff88"/><stop offset="60%" stop-color="#ffae00"/><stop offset="100%" stop-color="#ff0033"/></linearGradient>`;
  svg.appendChild(defs);
  // set dash
  const L = 2 * Math.PI * r / 2; // half circle length approx
  overlay.setAttribute("stroke-dasharray", `${(percent/100)*L} ${L}`);
  overlay.setAttribute("stroke-dashoffset", `${L - (percent/100)*L}`);
  svg.appendChild(overlay);

  cont.appendChild(svg);
}


document.addEventListener("DOMContentLoaded", ()=>{
  if(window.SpoofShield){
    drawGauge("gauge", window.SpoofShield.risk_score);
    const bars = document.getElementById("bars");
    const tf = window.SpoofShield.top_factors || {idn:0, logo:0, body:0};
    const items = [
      {label: "IDN / Homograph", value: tf.idn || 0},
      {label: "Logo Match (low=bad)", value: tf.logo || 0},
      {label: "Body Spam Prob", value: tf.body || 0}
    ];
    bars.innerHTML = "";
    items.forEach(it=>{
      const wrapper = document.createElement("div");
      wrapper.className = "bar-row";
      wrapper.innerHTML = `<div class="bar-label">${it.label}</div>
        <div class="bar-track"><div class="bar-fill" style="width:0%"></div></div>`;
      bars.appendChild(wrapper);
      setTimeout(()=> {
        const fill = wrapper.querySelector(".bar-fill");
        fill.style.width = Math.min(100, Math.max(0, it.value)) + "%";
      }, 300);
    });

    // PDF download button (simple client-side generation)
    const dl = document.getElementById("download-report");
    if(dl){
      dl.addEventListener("click", ()=> {
        // Prepare a simple text/popup or call backend to create PDF.
        // For now download JSON report
        const report = {
          risk_score: window.SpoofShield.risk_score,
          top_factors: window.SpoofShield.top_factors,
          features: window.SpoofShield.features || {}
        };
        const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'spoofshield_report.json'; document.body.appendChild(a); a.click();
        a.remove(); URL.revokeObjectURL(url);
      });
    }
  }
});

