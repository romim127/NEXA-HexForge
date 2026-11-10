"use strict";
const $=id=>document.getElementById(id);
const num=id=>{const raw=$(id).value.trim();if(!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(raw))throw Error("Usá números decimales o HEX con prefijo 0x.");const n=Number(raw);if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)throw Error("Valor fuera de rango de 32 bits.");return n;};
const hx=n=>"0x"+n.toString(16).toUpperCase();
function calculate(){
 try{
 const rva=num("rva"),va=num("va"),raw=num("raw"),size=num("size"),virtual=num("vsize"),delta=rva-va;
 if(delta<0){$("result").textContent="RVA fuera de esta sección.";$("steps").textContent="RVA < VirtualAddress.";$("meaning").textContent="Elegí otra sección.";return;}
 if(delta>=size){
 $("result").textContent=delta<virtual?"Zona virtual sin datos raw":"RVA fuera del rango raw";
 $("steps").textContent=hx(rva)+" − "+hx(va)+" = "+hx(delta)+"; SizeOfRawData = "+hx(size);
 $("meaning").textContent=delta<virtual?"Puede representar memoria inicializada en cero; no existe un byte físico correspondiente en esta sección.":"No se puede convertir este RVA mediante la sección indicada.";return;
 }
 const offset=raw+delta;
 $("result").textContent="File Offset = "+hx(offset)+" ("+offset+" decimal)";
 $("steps").textContent=hx(raw)+" + ("+hx(rva)+" − "+hx(va)+") = "+hx(offset);
 $("meaning").textContent="El RVA está respaldado por bytes raw según los metadatos de la sección. No prueba carga ni ejecución.";
 $("status").textContent="Cálculo completado.";
 }catch(e){$("status").textContent=e.message;$("result").textContent="";$("steps").textContent="";$("meaning").textContent="";}
}
async function load(){
 const file=$("file").files[0];if(!file){$("status").textContent="Seleccioná un archivo PE.";return;}
 try{
 const view=new DataView(await file.slice(0,Math.min(file.size,1048576)).arrayBuffer());
 const u16=p=>{if(p<0||p+2>view.byteLength)throw Error("Campo truncado.");return view.getUint16(p,true);};
 const u32=p=>{if(p<0||p+4>view.byteLength)throw Error("Campo truncado.");return view.getUint32(p,true);};
 if(u16(0)!==0x5a4d)throw Error("No hay firma MZ.");
 const pe=u32(0x3c);if(pe<64||pe+24>view.byteLength||u32(pe)!==0x4550)throw Error("Firma PE inválida.");
 const count=u16(pe+6),optSize=u16(pe+20),opt=pe+24,magic=u16(opt),table=opt+optSize;
 if(count>96||![0x10b,0x20b].includes(magic)||optSize<(magic===0x10b?96:112)||table+count*40>view.byteLength)throw Error("Tabla de secciones inválida.");
 const select=$("section");select.replaceChildren();
 for(let i=0;i<count;i++){
 const p=table+i*40,raw=u32(p+20),size=u32(p+16);
 if(size&&(raw===0||raw+size>file.size))throw Error("Sección fuera del archivo.");
 const bytes=new Uint8Array(view.buffer,p,8);const name=Array.from(bytes).filter(b=>b!==0).map(b=>b>=32&&b<=126?String.fromCharCode(b):"?").join("");
 const option=document.createElement("option");option.textContent=name||"Sección "+i;option.value=String(i);
 option.dataset.va=String(u32(p+12));option.dataset.raw=String(raw);option.dataset.size=String(size);option.dataset.vsize=String(u32(p+8));select.appendChild(option);
 }
 $("status").textContent="Secciones cargadas localmente. Elegí una.";
 select.dispatchEvent(new Event("change"));
 }catch(e){$("status").textContent="No se pudo leer PE: "+e.message;$("section").replaceChildren();}
}
$("section").addEventListener("change",()=>{
 const o=$("section").selectedOptions[0];if(!o)return;
 $("va").value=hx(Number(o.dataset.va));$("raw").value=hx(Number(o.dataset.raw));$("size").value=hx(Number(o.dataset.size));$("vsize").value=hx(Number(o.dataset.vsize));
 $("rva").value=hx(Number(o.dataset.va));calculate();
});
$("calculate").addEventListener("click",calculate);$("load").addEventListener("click",load);
calculate();
