"use strict";
const $=id=>document.getElementById(id);
const MAX_HEADER=1048576;
let sections=[],file=null;
function row(values){const tr=document.createElement("tr");values.forEach(value=>{const td=document.createElement("td");td.textContent=String(value);tr.appendChild(td);});return tr;}
function clear(){sections=[];$("section").replaceChildren();$("terms").replaceChildren();["entropy","bytes","unique"].forEach(id=>$(id).textContent="—");$("permissions").textContent="Seleccioná una sección.";}
async function inspect(){
  clear();file=$("file").files[0];if(!file){$("status").textContent="Seleccioná un archivo.";return;}
  try{
    if(file.size<64)throw Error("Cabecera DOS incompleta.");
    const view=new DataView(await file.slice(0,Math.min(file.size,MAX_HEADER)).arrayBuffer());
    const u16=p=>{if(p<0||p+2>view.byteLength)throw Error("Campo truncado.");return view.getUint16(p,true);};
    const u32=p=>{if(p<0||p+4>view.byteLength)throw Error("Campo truncado.");return view.getUint32(p,true);};
    if(u16(0)!==0x5A4D)throw Error("No hay firma MZ.");
    const pe=u32(0x3C);
    if(pe<64||pe+24>view.byteLength||u32(pe)!==0x4550)throw Error("Firma PE inválida.");
    const count=u16(pe+6),optSize=u16(pe+20),opt=pe+24,table=opt+optSize;
    if(count>96||table+count*40>view.byteLength)throw Error("Tabla de secciones fuera de límites.");
    const magic=u16(opt);
    if(![0x10B,0x20B].includes(magic)||optSize<(magic===0x10B?96:112))throw Error("Optional Header inválido.");
    for(let i=0;i<count;i++){
      const pos=table+i*40,rawSize=u32(pos+16),offset=u32(pos+20),flags=u32(pos+36);
      if(rawSize&&(offset===0||offset+rawSize>file.size))throw Error("Sección fuera del archivo.");
      const name=Array.from(new Uint8Array(view.buffer,pos,8)).filter(b=>b!==0).map(b=>b>=32&&b<=126?String.fromCharCode(b):"?").join("");
      sections.push({name,offset,rawSize,flags});
      const option=document.createElement("option");option.value=String(i);option.textContent=(name||"Sección "+i)+" · "+rawSize+" bytes";$("section").appendChild(option);
    }
    $("status").textContent="PE identificado. "+count+" secciones. Elegí una para estudiar.";
  }catch(e){clear();$("status").textContent="No se pudo analizar: "+e.message;}
}
async function calculate(){
  const index=Number($("section").value);
  if(!file||!sections[index]){$("status").textContent="Primero identificá las secciones.";return;}
  const s=sections[index];
  try{
    const sample=new Uint8Array(await file.slice(s.offset,s.offset+Math.min(s.rawSize,1048576)).arrayBuffer());
    const counts=new Uint32Array(256);sample.forEach(b=>counts[b]++);
    const n=sample.length,terms=[];let h=0;
    counts.forEach((count,b)=>{if(!count)return;const p=count/n,term=-p*Math.log2(p);h+=term;terms.push([b.toString(16).toUpperCase().padStart(2,"0"),count,p.toFixed(6),term.toFixed(6)]);});
    $("entropy").textContent=h.toFixed(4)+" bits/byte";$("bytes").textContent=n;$("unique").textContent=terms.length;
    $("terms").replaceChildren(...terms.map(row));
    $("permissions").textContent="Sección "+s.name+" · R="+Boolean(s.flags&0x40000000)+" W="+Boolean(s.flags&0x80000000)+" X="+Boolean(s.flags&0x20000000)+(s.rawSize>1048576?" · muestra parcial de 1 MiB":"");
    $("explain").textContent="H = suma de "+terms.length+" contribuciones; "+(n?"cada p(x) = frecuencia / "+n+".":"muestra vacía, entropía definida como 0.");
    $("status").textContent="Cálculo educativo completado; no se determina malicia ni ejecución.";
  }catch(e){$("status").textContent="No se pudo leer la sección.";}
}
$("inspect").addEventListener("click",inspect);$("calculate").addEventListener("click",calculate);
$("file").addEventListener("change",()=>{file=null;clear();$("status").textContent="Archivo cambiado. Identificá sus secciones.";});
