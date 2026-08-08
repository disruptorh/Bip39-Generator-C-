# Plan de Implementación — BIP-39 Seedphrase Generator (C++, Airgapped)

**Directorio de trabajo:** `/home/reimen/Escritorio/Projects/Bip39-Generator-C++/`
**Wordlist:** `bip39.txt` (2048 palabras, en la raíz del proyecto)

---

## 0. Objetivo del proyecto

Reescribir el generador de semillas BIP-39 (originalmente en Python/Tkinter) como una
aplicación de escritorio en C++, **100% offline y airgapped**, con:

- Generación de **una sola semilla por ejecución** (no lotes).
- Entropía base siempre provista por el CSPRNG del sistema operativo.
- Campo **opcional** para que el usuario aporte entropía/contraseña adicional, que se
  **suma** (nunca reemplaza) a la del SO.
- Medidor de entropía y nivel de seguridad **siempre visible** antes de generar.
- Sin logs, sin persistencia en disco por defecto, memoria segura, portapapeles seguro.

---

## 1. Alcance funcional (requisitos confirmados)

| Requisito | Detalle |
|---|---|
| Semillas por ejecución | Exactamente 1 |
| Longitud | 12 o 24 palabras, seleccionable |
| Entropía SO | Siempre presente, vía CSPRNG del sistema (obligatoria) |
| Entropía usuario | **Opcional**, campo de texto/passphrase libre |
| Indicador de entropía | **Siempre visible en pantalla**, aunque el usuario no aporte nada |
| Persistencia | Ninguna por defecto. Nada se escribe a disco salvo acción explícita del usuario |
| Logs | Ninguno en build de release |
| Clipboard | Copiado seguro con auto-limpieza por timeout |
| Red | Ninguna dependencia ni capacidad de red en el binario |

---

## 2. Stack tecnológico

| Componente | Elección | Motivo |
|---|---|---|
| Lenguaje | C++17/20 | RAII para zeroización automática, control fino de memoria |
| GUI | **Dear ImGui** (backend GLFW + OpenGL3) | Auditable (~30k líneas), sin dependencias de red, estático, ligero |
| Criptografía | **libsodium** | `randombytes_buf`, `crypto_kdf_hkdf_*`, `sodium_mlock`, `sodium_memzero` — API difícil de usar mal |
| Build | CMake + vcpkg/submódulos vendorizados | Reproducible, compilable sin red tras vendorizar dependencias |
| Plataforma inicial | Linux (X11/Wayland) | Luego portar a Windows si se requiere |

**Nota:** Qt se descarta por su enorme superficie de dependencias (red, SQL, XML) que
complica la auditoría de "cero capacidad de red" en el binario final.

---

## 3. Arquitectura de módulos

```
Bip39-Generator-C++/
├── bip39.txt                  # wordlist (ya existe)
├── CMakeLists.txt
├── third_party/
│   ├── imgui/                 # vendorizado
│   └── libsodium/             # vendorizado, compilado estático
└── src/
    ├── main.cpp
    ├── entropy/
    │   ├── entropy_mixer.hpp/.cpp   # HKDF: SO + usuario -> entropía final
    │   └── entropy_estimator.hpp/.cpp # heurística Shannon/zxcvbn-like
    ├── bip39/
    │   ├── wordlist.hpp/.cpp        # carga + verificación SHA-256 del wordlist
    │   └── mnemonic.hpp/.cpp        # checksum + mapeo a palabras
    ├── secure_mem/
    │   └── secure_buffer.hpp        # wrapper RAII: mlock + memzero garantizado
    ├── clipboard/
    │   └── secure_clipboard.hpp/.cpp # copiar + auto-clear con timer
    └── ui/
        ├── app.hpp/.cpp              # estado global de la app
        ├── screen_entropy_input.cpp  # pantalla 1: config + entropía opcional
        └── screen_reveal.cpp         # pantalla 2: mostrar semilla + medidor
```

---

## 4. Flujo de la aplicación (UX)

1. **Pantalla de configuración**
   - Selector de longitud: 12 / 24 palabras.
   - Campo de texto opcional: "Entropía adicional (opcional)" — el usuario puede
     dejarlo vacío sin penalización de seguridad, ya que la base del SO es obligatoria.
   - **Indicador de entropía y nivel de seguridad, siempre visible**, actualizado en
     tiempo real:
     - Entropía garantizada (fija): 128 bits (12 palabras) o 256 bits (24 palabras),
       etiquetada como "Seguridad garantizada por el sistema operativo".
     - Si el usuario escribe algo: una estimación heurística adicional, etiquetada
       claramente como "estimación no garantizada", para que nunca se confunda con
       la cifra de seguridad real.
   - Botón "Generar semilla".

2. **Pantalla de revelado**
   - Muestra la semilla generada (una sola), con advertencia de que se limpiará de
     memoria al cerrar/timeout.
   - Botón "Copiar al portapapeles" (auto-clear a los N segundos, configurable).
   - Botón "Nueva semilla" → vuelve al paso 1, sobrescribiendo de forma segura todo
     el estado anterior (entropía, semilla, input del usuario) antes de continuar.
   - Sin botón de "guardar en archivo" por defecto (ver sección 6 si se decide añadir
     como feature opcional futura, con cifrado).

---

## 5. Mezcla de entropía (SO + usuario)

Principio: el resultado nunca debe ser *más débil* que la entropía del SO sola.

```
entropia_so   = randombytes_buf(N)                  // libsodium, CSPRNG del SO
entrada_user  = bytes del campo opcional (puede ser vacío)

entropia_final = HKDF-SHA512(
                     ikm  = entropia_so || entrada_user,
                     salt = fijo/aplicación,
                     info = "bip39-entropy-v1"
                  )[:N bytes]
```

- Si el usuario no aporta nada, `entrada_user` es una cadena vacía y el resultado
  sigue siendo criptográficamente equivalente a `entropia_so` procesada por HKDF.
- El aporte del usuario **solo puede sumar** entropía, nunca puede degradar la salida
  por debajo del piso garantizado por el SO (propiedad de un extractor tipo HKDF).

---

## 6. Seguridad y hardening (airgapped)

- **Sin red:** no se linkea ninguna librería de sockets/HTTP; se documenta y,
  opcionalmente, se verifica en el script de build que el binario no referencia
  símbolos de red.
- **Sin logs:** ningún `fprintf`/logging a disco en build de release.
- **Memoria segura:** todo buffer que contenga entropía, input del usuario o la
  semilla usa `secure_buffer<T>` (RAII) con `sodium_mlock` al reservar y
  `sodium_memzero` garantizado al destruir, incluso en caminos de excepción.
- **Sin core dumps:** `setrlimit(RLIMIT_CORE, 0)` al iniciar el proceso.
- **Clipboard seguro:** contenido marcado como sensible donde la plataforma lo
  permita, y limpieza automática (sobrescritura + vaciado) tras timeout configurable.
- **Hardening de compilación:** `-fstack-protector-strong -D_FORTIFY_SOURCE=2
  -fPIE -pie`, RELRO completo, sin stack ejecutable.
- **Verificación del wordlist:** hash SHA-256 del `bip39.txt` embebido en el binario
  para detectar manipulación del archivo externo antes de usarlo.
- **Persistencia:** desactivada por defecto. Si en el futuro se quiere una opción de
  "guardar cifrado con passphrase", debe ser un feature explícito, separado y muy
  advertido en la UI — no forma parte de este plan inicial.

---

## 7. Fases de implementación

### Fase 1 — Núcleo criptográfico (sin UI)
- Vendorizar libsodium, compilar estático.
- Implementar `entropy_mixer` (HKDF) y pruebas contra vectores conocidos.
- Implementar `wordlist` (carga + verificación SHA-256) y `mnemonic` (checksum BIP-39
  + mapeo a palabras), validando contra vectores de prueba oficiales de BIP-39.
- Implementar `secure_buffer` y verificar con herramientas (valgrind/memcheck) que no
  quedan residuos tras destrucción.

### Fase 2 — Estimador de entropía
- Heurística Shannon sobre el input del usuario + longitud, con etiquetado claro de
  "estimación, no garantía".
- Cálculo del "nivel de seguridad" mostrado (ej. Bajo/Medio/Alto) basado siempre en
  la entropía garantizada del SO como piso.

### Fase 3 — UI con Dear ImGui
- Pantalla de configuración con el indicador de entropía en tiempo real.
- Pantalla de revelado con la semilla y controles de copiado/limpieza.
- Integración de `secure_clipboard` con timer de auto-clear.

### Fase 4 — Hardening y auditoría
- Aplicar flags de compilación de hardening.
- Revisar ausencia de símbolos de red en el binario final.
- Pruebas de memoria (mlock/memzero) y de que no se genera ningún archivo en disco
  durante el flujo normal.
- Auditoría de código completa (manual, ya que el proyecto es pequeño y crítico).

### Fase 5 — Empaquetado
- Build estático reproducible vía CMake.
- Documentación de compilación 100% offline (dependencias vendorizadas en el repo).
- Empaquetado como binario único para Linux (portabilidad a Windows si se requiere
  después).

---

## 8. Criterios de aceptación

- [ ] Genera correctamente semillas de 12 y 24 palabras válidas contra vectores de
      prueba oficiales de BIP-39.
- [ ] Con el campo de usuario vacío, la app funciona igual de bien y el indicador de
      entropía muestra la cifra garantizada del SO.
- [ ] Con el campo de usuario lleno, el indicador muestra ambas cifras (garantizada +
      estimada) claramente diferenciadas.
- [ ] Solo se genera una semilla por ejecución del flujo.
- [ ] No se crea ningún archivo en disco durante el flujo normal.
- [ ] No hay logging a disco en build de release.
- [ ] El portapapeles se limpia automáticamente tras el timeout configurado.
- [ ] El binario no contiene símbolos de red.
- [ ] Toda la memoria con material sensible se sobrescribe (verificado con
      valgrind/memcheck) al finalizar su uso.

---

## 9. Preguntas abiertas para siguiente iteración

- ¿Windows además de Linux, o solo Linux por ahora?
- ¿Timeout de auto-clear del clipboard configurable por el usuario o fijo (ej. 30s)?
- ¿Se quiere en el futuro una opción de guardado cifrado (con passphrase) como
  feature separado, o se mantiene la política de "nunca tocar disco"?
