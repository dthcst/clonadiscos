# DEPLOYMENT - CLONADISCOS / DISCOCLONER
**Fecha:** 2026-01-18 ~08:30
**Autor:** Martín + Claude

---

## URLs LIVE

| Dominio | Idioma | Estado |
|---------|--------|--------|
| **https://clonadiscos.com** | Español 🇪🇸 | ✅ LIVE |
| **https://discocloner.com** | English 🇬🇧 | ✅ LIVE |

---

## CONFIGURACIÓN CLOUDFLARE

### Workers
| Worker | Archivo | Ruta |
|--------|---------|------|
| clonadiscos | index.html (ES) | clonadiscos.com/* |
| discocloner | index.html (EN) | discocloner.com/* |

### DNS (ambos dominios)
- Tipo: A
- Nombre: @ (raíz)
- IPv4: 192.0.2.1
- Proxy: Activado (nube naranja)

### Cuenta Cloudflare
- Email: martinccv@gmail.com
- Plan: Free

---

## ARCHIVOS LOCALES

**Ubicación:** E:\_MEMMEM\_CLONADISCOS\_CLOUDFLARE\

```
index.html      → Landing español (clonadiscos.com)
index-en.html   → Landing inglés (discocloner.com)
```

---

## CARACTERÍSTICAS LANDING

- Diseño terminal aesthetic (dark cyan #00d4aa / black #0a0a0a)
- ASCII logo responsive
- 6 feature cards con iconos
- Tabla comparativa (ClonaDISCOS vs otros)
- Sección donaciones ARCAMIA con múltiples métodos:
  - IBAN (ES + SWIFT)
  - Bizum
  - PayPal
  - TWINT (Suiza)
  - Bitcoin
  - Ethereum  
  - BNB

---

## COMPLETADO 2026-01-20

- [x] **Botón descarga funcional** - Apunta a GitHub Releases
- [x] **GitHub Releases** - https://github.com/martin-cdm-dc/clonadiscos/releases/tag/v1.0
- [x] **Workers actualizados** - Desplegados con Wrangler

## PENDIENTE

- [ ] Añadir ruta www.clonadiscos.com/*
- [ ] Añadir ruta www.discocloner.com/*
- [ ] Crear registros DNS para www (CNAME → @)
- [ ] Marketing/difusión (Reddit, GitHub, YouTube)

---

## NOTAS

- SSL/HTTPS automático via Cloudflare
- CDN global incluido
- Protección DDoS incluida
- 100,000 requests/día gratis
