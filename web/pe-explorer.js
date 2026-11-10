"use strict";
const $=id=>document.getElementById(id);
function cell(row,text){const td=document.createElement("td");td.textContent=String(text);row.appendChild(td);}
function addRow(target,values){const tr=document.createElement("tr");values.forEach(v=>cell(tr,v));target.appendChild(tr);}
const HX=n=>"0x"+n.toString(16).toUpperCase().padStart(8,"0");
async function inspect(){
  $("fields").replaceChildren();$("sections").replaceChildren();
  const file=$("file").files[0];if(!file){$("status").textContent="Seleccioná un archivo.";return;}
  try{
    if(file.size<64)throw Error("Cabecera DOS incompleta.");
    const header=new DataView(await file.slice(0,Math.min(file.size,1048576)).arrayBuffer());
    const u16=p=>{if(p<0||p+2>header.byteLength)throw Error("Campo truncado.");return header.getUint16(p,true);};
    const u32=p=>{if(p<0||p+4>header.byteLength)throw Error("Campo truncado.");return header.getUint32(p,true);};
    if(u16(0)!==0x5A4D)throw Error("Firma MZ ausente.");
    const pe=u32(0x3C);
    if(pe<64||pe+24>header.byteLength||pe+24>file.size)throw Error("e_lfanew fuera de límites.");
    if(u32(pe)!==0x00004550)throw Error("Firma PE inválida.");
    const machine=u16(pe+4),count=u16(pe+6),optSize=u16(pe+20),opt=pe+24;
    if(count>96)throw Error("Cantidad de secciones fuera de límite.");
    const table=opt+optSize;
    if(table+count*40>header.byteLength||table+count*40>file.size)throw Error("Tabla de secciones truncada.");
    const magic=u16(opt);
    if(magic!==0x10B&&magic!==0x20B)throw Error("Optional Header no es PE32/PE32+.");
    if(optSize<(magic===0x10B?96:112))throw Error("Optional Header incompleto.");
    const fmt=magic===0x10B?"PE32":"PE32+";
    const entry=u32(opt+16);
    const base=magic===0x10B?"0x"+u32(opt+28).toString(16).toUpperCase():"0x"+header.getBigUint64(opt+24,true).toString(16).toUpperCase();
    const rows=[
      ["e_magic","0x00000000","4D 5A","Firma DOS MZ; no garantiza PE válido."],
      ["e_lfanew","0x0000003C",HX(pe),"Puntero de 32 bits little-endian al encabezado PE."],
      ["PE signature",HX(pe),"50 45 00 00","Firma PE y dos bytes nulos."],
      ["Machine",HX(pe+4),"0x"+machine.toString(16).toUpperCase().padStart(4,"0"),"Arquitectura declarada: "+({332:"x86",34404:"x86-64",43620:"ARM64"}[machine]||"otra")],
      ["NumberOfSections",HX(pe+6),count,"Cantidad de secciones declaradas."],
      ["OptionalHeader.Magic",HX(opt),"0x"+magic.toString(16).toUpperCase(),fmt],
      ["AddressOfEntryPoint",HX(opt+16),HX(entry),"RVA de entrada declarado; no demuestra ejecución."],
      ["ImageBase",HX(opt+(magic===0x10B?28:24)),base,"Base preferida de carga; ASLR puede modificarla."]
    ];
    rows.forEach(row=>addRow($("fields"),row));
    for(let i=0;i<count;i++){
      const pos=table+i*40;
      const nameBytes=new Uint8Array(header.buffer,pos,8);
      const name=Array.from(nameBytes).filter(x=>x!==0).map(x=>x>=32&&x<=126?String.fromCharCode(x):"?").join("");
      const rawSize=u32(pos+16),rawOffset=u32(pos+20),flags=u32(pos+36);
      if(rawSize&&(rawOffset===0||rawOffset+rawSize>file.size))throw Error("Sección "+i+" fuera del archivo.");
      addRow($("sections"),[name||"(sin nombre)",HX(u32(pos+12)),HX(rawOffset),rawSize,
        (flags&0x20000000?"X ":"")+(flags&0x80000000?"W ":"")+(flags&0x40000000?"R":"")]);
    }
    $("status").textContent=fmt+" · "+count+" secciones · inspección estructural completada sin ejecución.";
  }catch(e){$("status").textContent="No se pudo interpretar como PE: "+e.message;$("fields").replaceChildren();$("sections").replaceChildren();}
}
$("inspect").addEventListener("click",inspect);
$("file").addEventListener("change",()=>{$("status").textContent="Archivo seleccionado. Pulsá Inspeccionar."; $("fields").replaceChildren();$("sections").replaceChildren();});
