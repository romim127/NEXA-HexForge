"use strict";
// Calculadora local, sin red ni evaluación dinámica.
const el = id => document.getElementById(id);
const HEX = "0123456789ABCDEF";
function convertHex(value) {
  const clean = value.trim().toUpperCase().replace(/^0X/, "").replace(/\s/g, "");
  if (!/^[0-9A-F]{1,16}$/.test(clean)) throw Error("Ingresá entre 1 y 16 dígitos HEX (0–9, A–F).");
  const steps = [...clean].map((digit,i) => {
    const decimal = HEX.indexOf(digit);
    const nibble = decimal.toString(2).padStart(4,"0");
    const power = clean.length-1-i;
    const contribution = BigInt(decimal)*16n**BigInt(power);
    return {digit, decimal, nibble, power, contribution};
  });
  return {binary:steps.map(s=>s.nibble).join(""),decimal:steps.reduce((s,x)=>s+x.contribution,0n),steps};
}
function convertBinary(value) {
  const bits = value.trim().replace(/\s/g, "");
  if (!/^[01]{1,64}$/.test(bits)) throw Error("Ingresá entre 1 y 64 bits.");
  const padded = bits.padStart(Math.ceil(bits.length/4)*4,"0");
  const groups = padded.match(/.{4}/g);
  return {padded,steps:groups.map(g=>({nibble:g,decimal:parseInt(g,2),digit:HEX[parseInt(g,2)]})),
          hex:groups.map(g=>HEX[parseInt(g,2)]).join("")};
}
function cell(tag,text){const n=document.createElement(tag);n.textContent=String(text);return n;}
function render(){
  el("error").textContent="";el("steps").replaceChildren();el("head").replaceChildren();
  try{
    const isHex=el("mode").value==="hex";
    const r=isHex?convertHex(el("value").value):convertBinary(el("value").value);
    el("result").textContent=isHex?r.binary:r.hex;
    el("summary").textContent=isHex?"Decimal: "+r.decimal.toString():"Binario agrupado: "+r.padded;
    const headings=isHex?["HEX","Decimal","4 bits","Potencia","Aporte decimal"]:["4 bits","Decimal","HEX"];
    const tr=document.createElement("tr");headings.forEach(x=>tr.appendChild(cell("th",x)));el("head").appendChild(tr);
    r.steps.forEach(s=>{
      const row=document.createElement("tr");
      (isHex?[s.digit,s.decimal,s.nibble,"16^"+s.power,s.contribution.toString()]:[s.nibble,s.decimal,s.digit])
        .forEach(x=>row.appendChild(cell("td",x)));
      el("steps").appendChild(row);
    });
    el("formula").textContent=isHex?
      "Suma de aportes: "+r.steps.map(s=>s.decimal+" × 16^"+s.power).join(" + ")+" = "+r.decimal:
      "Cada grupo de cuatro bits representa un dígito HEX. Ejemplo: 1010 = 8 + 0 + 2 + 0 = 10 = A.";
  }catch(e){el("result").textContent="";el("summary").textContent="";el("formula").textContent="";el("error").textContent=e.message;}
}
el("calculate").addEventListener("click",render);
el("mode").addEventListener("change",()=>{el("value").value=el("mode").value==="hex"?"AF":"10101111";render();});
el("value").addEventListener("keydown",e=>{if(e.key==="Enter")render();});
render();
