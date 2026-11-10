"""A5: explicaciones de importaciones PE; nunca infiere ejecución."""
from pathlib import Path
from .imports import inspect_imports

CATALOG = {
    "virtualalloc": ("memory", "Reserva memoria virtual; habitual en aplicaciones, JIT y cargadores."),
    "virtualprotect": ("memory", "Modifica protecciones de memoria; puede ser legítimo o requerir revisión contextual."),
    "createremotethread": ("process", "Crea un hilo en otro proceso; requiere correlación antes de inferir inyección."),
    "writeprocessmemory": ("process", "Escribe memoria de otro proceso; se utiliza también en depuración."),
    "readprocessmemory": ("process", "Lee memoria de otro proceso; común en depuración y herramientas de diagnóstico."),
    "createprocessw": ("process", "Inicia procesos; operación habitual del sistema."),
    "createprocessa": ("process", "Inicia procesos; variante ANSI."),
    "regsetvalueexw": ("registry", "Escribe un valor de registro; frecuente en instaladores y configuradores."),
    "regopenkeyexw": ("registry", "Abre claves del registro de Windows."),
    "internetopena": ("network", "Inicializa servicios WinINet; puede utilizarse en software legítimo."),
    "internetopenw": ("network", "Inicializa servicios WinINet; puede utilizarse en software legítimo."),
    "winhttpconnect": ("network", "Establece un contexto de conexión WinHTTP."),
    "cryptencrypt": ("crypto", "Cifra datos; uso habitual en seguridad y aplicaciones."),
    "bcryptencrypt": ("crypto", "Cifra datos mediante CNG; no implica ransomware."),
    "loadlibraryw": ("dynamic_loading", "Carga una biblioteca DLL en tiempo de ejecución."),
    "getprocaddress": ("dynamic_loading", "Resuelve direcciones de funciones exportadas dinámicamente."),
}
def explain_imports(path: str | Path) -> dict:
    parsed = inspect_imports(path)
    groups = []
    for item in parsed["imports"]:
        functions = []
        for function in item["functions"]:
            if "name" in function:
                name = function["name"]
                category, explanation = CATALOG.get(name.casefold(), ("unclassified", "Función importada sin ficha educativa específica."))
                functions.append({"name": name, "category": category, "explanation": explanation,
                                  "evidence": "static_import_only", "called": "unknown"})
            else:
                functions.append({"ordinal": function["ordinal"], "category": "ordinal",
                                  "explanation": "Importación por ordinal; el nombre depende de la DLL y su versión.",
                                  "evidence": "static_import_only", "called": "unknown"})
        groups.append({"dll": item["dll"], "functions": functions})
    return {"module": "Academy A5", "status": parsed["status"], "dlls": groups,
            "dll_count": len(groups), "function_count": sum(len(g["functions"]) for g in groups),
            "execution_performed": False, "verdict": "not_determined",
            "limitations": ["Importar una API no prueba que se invoque.",
                            "Una API puede tener usos legítimos y maliciosos.",
                            "No se observan imports dinámicos, delay-load ni llamadas reales.",
                            "El catálogo es orientativo y no constituye clasificación de malware."]}
