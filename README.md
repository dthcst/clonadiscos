# CLONADISCOS v2.0.0
## Clonado de discos RAPIDO
### Velocidad similar a AOMEI/Clonezilla

---

## NUEVO EN v2.0

- **WIMLIB integrado** - Mucho más rápido que DISM
- **VSS automático** - Clona discos en uso sin problemas
- **100-200+ MB/s** - Velocidad real, no teórica
- **Sin compresión** - Máxima velocidad de transferencia

---

## USO

1. Doble click en **CLONADISCOS.bat**
2. Acepta permisos de administrador
3. Pulsa **[F]** para clonar rápido
4. Sigue las instrucciones

---

## ¿QUÉ PUEDE HACER?

### CLONAR
- **[F] Clonar RAPIDO** - WIMLIB + VSS (RECOMENDADO)
- **[2] Clonar DETALLADO** - Robocopy (lento, muestra archivos)

### HERRAMIENTAS
- **Ver discos** - Detecta todos los discos conectados
- **Rescatar disco** - Recupera discos ocultos/invisibles
- **Borrar disco** - Limpia y formatea (GPT/MBR, NTFS/exFAT)
- **Health Check** - Comprueba SMART y estado del disco

---

## VELOCIDADES

| Método | MBR | GPT | Disco en uso | Velocidad |
|--------|-----|-----|--------------|-----------|
| **WIMLIB** | ✅ | ✅ | ✅ (VSS) | **100-200+ MB/s** |
| Robocopy | ✅ | ✅ | ⚠️ (salta) | ~50-80 MB/s |

---

## CONTENIDO

```
CLONADISCOS/
├── CLONADISCOS.bat         ← EJECUTA ESTO
├── _DEV/
│   ├── CLONADISCOS.ps1     ← Script principal
│   └── tools/
│       ├── wimlib-imagex.exe  ← Motor de clonado (GPL v3)
│       ├── libwim-15.dll
│       └── CMTrace.exe        ← Visor de logs
├── sounds/
│   └── bark.wav            ← Ladrido de Nala
└── README.md
```

---

## CARACTERÍSTICAS

- ✅ **Rápido** - WIMLIB más rápido que DISM nativo
- ✅ **VSS** - Clona discos en uso (snapshot)
- ✅ **MBR + GPT** - Soporta ambos tipos de partición
- ✅ **LOG automático** - Todo queda registrado
- ✅ **Barra de progreso** - Velocidad en tiempo real
- ✅ **Bootloader** - Repara automáticamente
- ✅ **Protección** - No puedes borrar disco de Windows
- ✅ **Licencia GPL** - 100% libre y redistribuible

---

## LOGS

Los logs se guardan en:
```
%USERPROFILE%\Documents\ARCAMIA-MEMMEM\Logs\CLONADISCOS\
```

Usa **CMTrace** (incluido) para ver logs en tiempo real.

---

## REQUISITOS

- Windows 10/11
- Permisos de administrador
- 2 discos (origen + destino)

---

## DEPENDENCIAS

| Componente | Versión | Licencia |
|------------|---------|----------|
| wimlib-imagex | 1.14.4 | GPL v3 |
| libwim-15.dll | 1.14.4 | GPL v3 |
| CMTrace | - | Microsoft (redistribuible) |

WIMLIB: https://wimlib.net - Eric Biggers

---

## ADVERTENCIA

⚠️ **CLONAR BORRA EL DISCO DESTINO**

El programa pide confirmación escribiendo "CLONAR" antes de proceder.

---

## 100% GRATUITO

Sin publicidad. Sin trucos. Sin límites.
Licencia GPL v3 para componentes de terceros.

---

## CRÉDITOS

- **WIMLIB** - Eric Biggers (GPL v3)
- **Desarrollo** - CLAUDE CODE (Anthropic)
- **Concepto** - ARCAMIA MEMMEM

---

**clonadiscos.com** | **discocloner.com**

**COSTA DA MORTE** · **DEATH COAST** → www.costa-da-morte.com

2026
