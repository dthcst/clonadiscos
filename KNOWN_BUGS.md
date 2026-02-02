# KNOWN BUGS - CLONADISCOS
**Última actualización:** 2026-01-21

---

## BUGS CONOCIDOS

### 1. FFU no funciona con discos MBR
- **Error:** 50 (0x80070032) - "The request is not supported"
- **Causa:** DISM /Capture-FFU solo soporta discos GPT
- **Workaround:** Usar WIM o Robocopy para discos MBR
- **Estado:** Won't fix (limitación de Windows)

### 2. WIM falla con archivos en uso (Error 32)
- **Error:** 32 - "The process cannot access the file because it is being used by another process"
- **Causa:** Windows bloquea archivos del sistema mientras está en ejecución
- **Workaround:**
  - Usar Robocopy (salta archivos bloqueados)
  - Arrancar desde WinPE
  - Conectar disco a otro PC
- **Estado:** Won't fix (limitación de Windows)

### 3. Robocopy lento comparado con clonación sectorial
- **Síntoma:** ~80 MB/s vs 150+ MB/s de clonación bit-a-bit
- **Causa:** Copia archivo por archivo, no por sectores
- **Workaround:** Usar para discos pequeños o cuando FFU/WIM no funcionan
- **Estado:** Aceptado (tradeoff por compatibilidad)

---

## LIMITACIONES CONOCIDAS

| Método | MBR | GPT | Archivos en uso | Velocidad |
|--------|-----|-----|-----------------|-----------|
| FFU    | ❌  | ✅  | ❌              | Rápido    |
| WIM    | ✅  | ✅  | ❌              | Medio     |
| Robocopy | ✅ | ✅ | ✅ (salta)      | Lento     |

---

## RECOMENDACIÓN POR CASO

1. **Disco Windows apagado (otro PC/WinPE):** FFU si GPT, WIM si MBR
2. **Disco Windows encendido (en uso):** Robocopy única opción
3. **Disco de datos (sin Windows):** Cualquiera funciona

---

## HISTORIAL

- **2026-01-21:** Documentados bugs FFU y WIM tras testing real
