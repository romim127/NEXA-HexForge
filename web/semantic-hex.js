"use strict";
const $=id=>document.getElementById(id), labels=new Map();
let preview=new Uint8Array(),selected=-1;
function mark(start,len,kind,label){for(let i=start;i<start+len;i++)labels.set(i,{kind,label,start,len});}
function hex(n,width=2){return n.toString(16).toUpperCase().padStart(width,"0");}
function fieldExplanation(index,info){
  if(!info)return "Interpretación: byte individual sin estructura anotada.\nVerificación: correlacionar con el formato y los offsets del archivo; un valor aislado no indica malware.";
  const data=Array.from(preview.slice(info.start,Math.min(info.start+info.len,preview.length)));
  const bytes=data.map(x=>hex(x)).join(" ");
  const bitString=data.map(x=>x.toString(2).padStart(8,"0")).join(" ");
  let value=0n;
  for(let i=data.length-1;i>=0;i--)value=value*256n+BigInt(data[i]);
  const little="0x"+value.toString(16).toUpperCase();
  const common="Campo: "+info.label+"\nRango: 0x"+hex(info.start,8)+"..0x"+hex(info.start+info.len-1,8)+"\nBytes: "+bytes+"\nBits: "+bitString+"\n";
  if(info.kind==="pointer")return common+"Cálculo little-endian: "+data.map((v,i)=>hex(v)+" × 256^"+i).join(" + ")+" = "+value.toString()+" ("+little+").\nSignificado: e_lfanew apunta al encabezado PE.\nVerificación: comprobar firma PE\\\\0\\\\0 y límites del archivo en el offset calculado.";
  if(info.kind==="machine")return common+"Cálculo little-endian: "+data.map((v,i)=>hex(v)+" × 256^"+i).join(" + ")+" = "+value.toString()+" ("+little+").\nSignificado: identificador de arquitectura COFF.\nVerificación: contrastar con encabezado opcional y estructura PE.";
  if(info.kind==="mz")return common+"Cálculo: 4D = 77 = M (ASCII); 5A = 90 = Z (ASCII).\nSignificado: firma DOS MZ.\nVerificación: leer e_lfanew (offset 0x3C) y comprobar PE\\\\0\\\\0.";
  if(info.kind==="pe")return common+"Cálculo ASCII: 50 = P, 45 = E, 00 y 00 son bytes nulos.\nSignificado: firma del encabezado PE.\nVerificación: revisar COFF, cabecera opcional y límites de secciones.";
  if(info.kind==="zip")return common+"Significado: firma de estructura ZIP; no determina el contenido interno.\nVerificación: enumerar entradas sin ejecutarlas; validar rutas y tipos de archivo.";
  return common+"Verificación: contrastar estructura con documentación del formato.";
}
function detail(index){
  const value=preview[index],info=labels.get(index),bits=value.toString(2).padStart(8,"0");
  const weights=[128,64,32,16,8,4,2,1].filter((w,i)=>bits[i]==="1");
  $("detail").textContent="BYTE SELECCIONADO\nOffset: 0x"+hex(index,8)+" ("+index+")\nHexadecimal: "+hex(value)+"\nBinario: "+bits+"\nDecimal: "+value+"\nASCII: "+(value>=32&&value<=126?String.fromCharCode(value):"no imprimible")+"\nPesos activos: "+(weights.join(" + ")||"0")+" = "+value+"\n\nESTRUCTURA Y RAZONAMIENTO\n"+fieldExplanation(index,info)+"\n\nRegla pericial: la estructura del archivo no demuestra ejecución ni comportamiento malicioso.";
  document.querySelectorAll(".byte.selected").forEach(b=>b.classList.remove("selected"));
  const button=document.querySelector('.byte[data-offset="'+index+'"]');
  if(button){button.classList.add("selected");button.setAttribute("aria-pressed","true");}
  document.querySelectorAll('.byte[aria-pressed="true"]').forEach(b=>{if(b!==button)b.setAttribute("aria-pressed","false");});
  selected=index;
}
function render(){const table=document.createElement("table"),head=document.createElement("tr");["OFFSET","HEX BYTES (16 por fila)","ASCII"].forEach(x=>{const th=document.createElement("th");th.textContent=x;head.append(th);});table.append(head);for(let base=0;base<preview.length;base+=16){const tr=document.createElement("tr"),off=document.createElement("td"),cell=document.createElement("td"),ascii=document.createElement("td");off.className="off";off.textContent=hex(base,8);for(let i=base;i<Math.min(base+16,preview.length);i++){const b=document.createElement("button");b.type="button";b.className="byte";b.textContent=hex(preview[i]);b.dataset.offset=i;b.dataset.kind=labels.get(i)?.kind||"";b.title=labels.get(i)?.label||"Byte "+i;b.addEventListener("click",()=>detail(i));cell.append(b);}ascii.className="ascii";ascii.textContent=Array.from(preview.slice(base,base+16),b=>b>=32&&b<=126?String.fromCharCode(b):".").join("");tr.append(off,cell,ascii);table.append(tr);}$("grid").replaceChildren(table);}
async function inspect(){const file=$("file").files?.[0];if(!file){$("status").textContent="Seleccioná un archivo.";return;}labels.clear();selected=-1;try{const prefix=new Uint8Array(await file.slice(0,Math.min(file.size,1048576)).arrayBuffer());preview=prefix.slice(0,4096);if(prefix.length>=2&&prefix[0]===0x4d&&prefix[1]===0x5a){mark(0,2,"mz","MZ: firma DOS. No demuestra por sí sola un PE válido.");if(prefix.length>=0x40){const v=new DataView(prefix.buffer,prefix.byteOffset,prefix.byteLength),ptr=v.getUint32(0x3c,true);if(ptr>=0x40&&ptr<=prefix.length-24&&prefix[ptr]===0x50&&prefix[ptr+1]===0x45&&prefix[ptr+2]===0&&prefix[ptr+3]===0){mark(0x3c,4,"pointer","e_lfanew: entero little-endian = 0x"+hex(ptr,8)+" ("+ptr+"); señala encabezado PE.");mark(ptr,4,"pe","Firma PE\\0\\0 validada en el offset indicado por e_lfanew.");const machine=v.getUint16(ptr+4,true);mark(ptr+4,2,"machine","COFF Machine: 0x"+hex(machine,4)+" ("+({332:"Intel 386",34404:"AMD64",43620:"ARM64"}[machine]||"arquitectura no identificada")+").");}}}else if(prefix.length>=4&&prefix[0]===0x50&&prefix[1]===0x4b&&((prefix[2]===3&&prefix[3]===4)||(prefix[2]===5&&prefix[3]===6)||(prefix[2]===7&&prefix[3]===8))){mark(0,4,"zip","Firma ZIP compatible. La extensión no es evidencia suficiente del contenido.");}
render();$("status").textContent="Archivo: "+file.name+" · Tamaño: "+file.size+" bytes · Vista: "+preview.length+" bytes · Sin ejecución.";if(preview.length)detail(0);else $("detail").textContent="Archivo vacío.";}catch(err){$("status").textContent="No se pudo leer el archivo: "+err.message;}}
$("load").addEventListener("click",inspect);
