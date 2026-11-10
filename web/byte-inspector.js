"use strict";
const $ = id => document.getElementById(id);
const WEIGHTS = [128,64,32,16,8,4,2,1];
const state = {offset:0,data:new Uint8Array(0)};
function node(tag,value){const e=document.createElement(tag);e.textContent=String(value);return e;}
function showByte(index){
  if(index<0||index>=state.data.length)return;
  const value=state.data[index],absolute=state.offset+index,bits=value.toString(2).padStart(8,"0");
  const hx=value.toString(16).toUpperCase().padStart(2,"0");
  $("selected").textContent="Offset "+absolute+" (0x"+absolute.toString(16).toUpperCase().padStart(8,"0")+") · HEX "+hx+" · DEC "+value+" · ASCII "+(value>=32&&value<=126?String.fromCharCode(value):"(no imprimible)");
  $("bits").replaceChildren();
  const terms=[];
  [...bits].forEach((bit,i)=>{
    const box=node("div","");box.className="bit";
    box.appendChild(node("strong",bit));box.appendChild(node("small",WEIGHTS[i]));
    $("bits").appendChild(box);terms.push(bit+"×"+WEIGHTS[i]);
  });
  $("formula").textContent=terms.join(" + ")+" = "+value;
  $("meaning").textContent="Cada bit activo aporta su peso; la suma es el valor decimal.";
  document.querySelectorAll(".byte").forEach((e,i)=>e.setAttribute("aria-pressed",String(i===index)));
}
async function readBytes(){
  const file=$("file").files[0];
  if(!file){$("status").textContent="Seleccioná un archivo.";return;}
  const offset=Number($("offset").value);
  if(!Number.isSafeInteger(offset)||offset<0||offset>=file.size){$("status").textContent="Offset inválido o archivo vacío.";return;}
  $("status").textContent="Leyendo...";
  try{
    const data=new Uint8Array(await file.slice(offset,Math.min(offset+32,file.size)).arrayBuffer());
    state.offset=offset;state.data=data;$("bytes").replaceChildren();
    data.forEach((value,i)=>{
      const button=node("button",value.toString(16).toUpperCase().padStart(2,"0"));
      button.type="button";button.className="byte";button.title="Offset "+(offset+i);
      button.setAttribute("aria-label","Byte "+(i+1)+", offset "+(offset+i));
      button.addEventListener("click",()=>showByte(i));$("bytes").appendChild(button);
    });
    $("status").textContent="Leídos "+data.length+" bytes desde offset "+offset+".";
    showByte(0);
  }catch(e){$("status").textContent="No se pudo leer el archivo.";$("bytes").replaceChildren();}
}
$("read").addEventListener("click",readBytes);
$("file").addEventListener("change",()=>{
  $("status").textContent="Archivo seleccionado. Pulsá Leer 32 bytes.";
  $("bytes").replaceChildren();$("bits").replaceChildren();
  $("selected").textContent="Esperando lectura...";$("formula").textContent="";$("meaning").textContent="";
});
