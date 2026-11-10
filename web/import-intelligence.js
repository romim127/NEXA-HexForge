"use strict";
const $=id=>document.getElementById(id);
const catalog={
 virtualalloc:["Memoria","Reserva memoria virtual; común en software legítimo y JIT."],
 virtualprotect:["Memoria","Modifica protecciones de páginas; requiere contexto."],
 createremotethread:["Procesos","Crea hilos en otro proceso; no prueba inyección."],
 writeprocessmemory:["Procesos","Escribe memoria de otro proceso; también se usa en depuración."],
 readprocessmemory:["Procesos","Lee memoria de otro proceso; habitual en diagnóstico."],
 createprocessw:["Procesos","Inicia procesos; función normal de Windows."],
 loadlibraryw:["Carga dinámica","Carga una DLL en tiempo de ejecución."],
 getprocaddress:["Carga dinámica","Resuelve direcciones de funciones exportadas."],
 winhttpconnect:["Red","Configura conexión WinHTTP."],
 bcryptencrypt:["Criptografía","Cifra datos; no implica ransomware."]
};
function addRow(values){const tr=document.createElement("tr");values.forEach(v=>{const td=document.createElement("td");td.textContent=String(v);tr.appendChild(td);});$("rows").appendChild(tr);}
async function inspect(){
 $("rows").replaceChildren();const file=$("file").files[0];if(!file){$("status").textContent="Seleccioná un archivo.";return;}
 try{
 const limit=Math.min(file.size,1048576);const header=new DataView(await file.slice(0,limit).arrayBuffer());
 const u16=p=>{if(p<0||p+2>header.byteLength)throw Error("Cabecera truncada.");return header.getUint16(p,true);};
 const u32=p=>{if(p<0||p+4>header.byteLength)throw Error("Cabecera truncada.");return header.getUint32(p,true);};
 if(u16(0)!==0x5A4D)throw Error("Firma MZ ausente.");
 const pe=u32(0x3C);if(pe<64||pe+24>header.byteLength||u32(pe)!==0x4550)throw Error("Firma PE inválida.");
 const n=u16(pe+6),os=u16(pe+20),opt=pe+24,magic=u16(opt);
 if(n>96||![0x10B,0x20B].includes(magic)||os<(magic===0x10B?96:112))throw Error("Optional Header inválido.");
 const table=opt+os;if(table+n*40>header.byteLength)throw Error("Tabla de secciones truncada.");
 const sections=[];for(let i=0;i<n;i++){const p=table+i*40;const raw=u32(p+16),off=u32(p+20);if(raw&&(off===0||off+raw>file.size))throw Error("Sección fuera de archivo.");sections.push({rva:u32(p+12),raw,off});}
 const rvaOffset=(rva,len=1)=>{for(const s of sections)if(rva>=s.rva&&rva-s.rva+len<=s.raw)return s.off+rva-s.rva;throw Error("RVA fuera de sección respaldada.");};
 const read=async(rva,len)=>new DataView(await file.slice(rvaOffset(rva,len),rvaOffset(rva,len)+len).arrayBuffer());
 const string=async rva=>{const off=rvaOffset(rva);const data=new Uint8Array(await file.slice(off,Math.min(off+512,file.size)).arrayBuffer());const end=data.indexOf(0);if(end<0)throw Error("Cadena sin terminador.");return Array.from(data.slice(0,end)).map(x=>String.fromCharCode(x)).join("");};
 const count=u32(opt+(magic===0x10B?92:108));if(count<2){$("status").textContent="Sin directorio de importaciones declarado.";return;}
 const dir=opt+(magic===0x10B?96:112)+8;if(dir+8>opt+os)throw Error("Directorio fuera del encabezado.");
 const importRva=u32(dir),importSize=u32(dir+4);if(!importRva||!importSize){$("status").textContent="Directorio de importaciones vacío.";return;}
 const width=magic===0x10B?4:8;let dlls=0,functions=0,terminated=false;
 for(let i=0;i<Math.min(128,Math.floor(importSize/20));i++){
 const d=await read(importRva+i*20,20);const oft=d.getUint32(0,true),name=d.getUint32(12,true),ft=d.getUint32(16,true);
 if(!oft&&!name&&!ft&&!d.getUint32(4,true)&&!d.getUint32(8,true)){terminated=true;break;}
 if(!name)throw Error("Descriptor sin nombre DLL.");
 const dll=await string(name);dlls++;let done=false;
 for(let j=0;j<512;j++){
 const t=await read((oft||ft)+j*width,width);
 const val=width===4?BigInt(t.getUint32(0,true)):t.getBigUint64(0,true);
 if(val===0n){done=true;break;}
 const ordinalFlag=1n<<BigInt(width*8-1);let api;
 if(val&ordinalFlag)api="#"+(val&65535n).toString();
 else {if(val>0xffffffffn)throw Error("RVA de nombre inválido.");api=await string(Number(val)+2);}
 const info=catalog[api.toLowerCase()]||["Sin clasificar","Importación estática: no demuestra que haya sido invocada."];
 addRow([dll,api,info[0],info[1]]);functions++;
 }
 if(!done)throw Error("Límite de funciones alcanzado.");
 }
 if(!terminated)throw Error("Directorio de imports sin terminador dentro del límite.");
 $("status").textContent=dlls+" DLL y "+functions+" funciones declaradas; ejecución NO observada.";
 }catch(e){$("rows").replaceChildren();$("status").textContent="No se pudo analizar: "+e.message;}
}
$("inspect").addEventListener("click",inspect);
$("file").addEventListener("change",()=>{$("rows").replaceChildren();$("status").textContent="Archivo seleccionado. Pulsá Examinar importaciones.";});
