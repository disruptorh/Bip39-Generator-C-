# BIP-39 Seedphrase Generator (C++)

Generador de frases semilla BIP-39 y billeteras HD para Linux, de escritorio y
100% airgapped. Interfaz Dear ImGui + GLFW + OpenGL3, ~3.7k líneas propias.

Dos modos de operación:

- **Una semilla** — se muestra en pantalla, con sus direcciones EVM y BTC ya
  derivadas y botones de copia con auto-clear.
- **Lote** — genera N semillas, ofusca cada una con la contraseña que indiques y
  exporta un `.txt` (semilla obfuscada + sus direcciones) con escritura atómica.

- Sin red: build reproducible con dependencias vendored, filtro seccomp-BPF que
  bloquea `socket()` AF_INET/AF_INET6, test de CTest que verifica que el binario
  no exporta símbolos de red, y perfil AppArmor opcional (`deny network`).
- Sin escritura automática a disco: ni estado de ventana de ImGui, ni caches de
  shaders de OpenGL, ni core dumps (`RLIMIT_CORE = 0`). El único archivo que se
  crea es el `.txt` de exportación que el usuario nombra explícitamente.
- Material sensible en memoria `mlock`'ed y auto-zeroed (RAII en todos los caminos).
- Lista de palabras embebida en el binario, con verificación SHA-256 si se
  supplya un `bip39.txt` externo.

## Requisitos

- CMake ≥ 3.20, compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- libsodium, libsecp256k1 y Dear ImGui: **ya vendored**, no se descargan.
  Inicializa los submódulos si aún no lo están:
  `git submodule update --init --recursive`.
- libsodium se compila estático vía autotools como `ExternalProject` (la primera
  build tarda algo más).
- GLFW3, X11 y OpenGL (dev headers) del sistema: `pkg-config glfw3 x11`.
- `ulimit -l unlimited` recomendado (los buffers se bloquean en RAM con `mlock`).

## Build y tests

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/bip39_generator            # GUI (puede usarse con xvfb-run)
```

Opcionales:

```sh
cmake -S . -B build -DBIP39_BUILD_TESTS=OFF      # sin suite de tests
xvfb-run -a ./build/bip39_generator              # GUI sin pantalla
```

### Tests incluidos

| Target CTest | Qué cubre |
|---|---|
| `bip39_tests` | Vectores BIP-39 oficiales, wordlist + digest, mezclador de entropía, buffers seguros, direcciones EVM/BTC, export batch |
| `clipboard_x11` | Portapapeles X11 real (se salta solo si no hay display) |
| `no_network_symbols` | `nm -D` sobre el binario: ninguna tabla dinámica con símbolos de red/DNS/shell/`dlopen` |

### Test end-to-end de la GUI

```sh
scripts/e2e_gui_test.sh            # necesita xvfb, xdotool y xclip
```

Levanta un display Xvfb limpio (`HOME` temporal), conduce la app con teclado y
verifica cada botón de copia contra la selección CLIPBOARD, el auto-clear y que
no se persiste nada bajo `$HOME`.

## Uso

1. Elige el modo (una semilla o varias) y la longitud (12 o 24 palabras).
2. Opcionalmente escribe entropía adicional: se mezcla con la del SO mediante
   HKDF-SHA512, así que nunca *reemplaza* la entropía del sistema. El medidor
   muestra la Bits estimados (estimación heurística de Shannon, no una garantía
   criptográfica; el suelo garantizado es el CSPRNG del sistema).
3. En modo **una semilla**, las direcciones se derivan de la frase ya revelada:
   - EVM: `m/44'/60'/0'/0/0` (checksum EIP-55)
   - BTC: `m/84'/0'/0'/0/0` (SegWit nativo P2WPKH, bech32)
   El portapapeles se auto-limpia a los 30 s (configurable con
   `BIP39_CLIPBOARD_TIMEOUT_MS`).
4. En modo **lote**, cada semilla se ofusca con XOR de una clave derivada por
   PBKDF2-HMAC-SHA256 (KDF v1, compatible con la app BIP-39 Obfuscator) y se
   escribe con `O_EXCL` + renombrado atómico, avisando si el archivo existe.

## Estructura

```
src/
  main.cpp            # init GLFW/ImGui + hardening de runtime
  secure_mem/         # buffers mlock'ed, secure_string, secure_buffer
  entropy/            # random_bytes (libsodium) + HKDF mix + estimador
  bip39/              # wordlist (con digest) y entropy_to_mnemonic
  crypto/             # keccak256, ripemd160, base58, pbkdf2, kdf, seed_transformer
  bip32/              # derivación HD (master + derive_path + fingerprint)
  address/            # evm.cpp, btc.cpp, bech32, addresses (orquestador)
  export/             # batch_export: render del .txt + escritura atómica
  clipboard/          # portapapeles X11 con auto-clear
  security/           # seccomp-BPF (bloquea sockets de red)
  ui/                 # app (estado) + pantallas config/reveal/batch
tests/                # suite propia + vectores BIP-39 + test de portapapeles
scripts/              # check_no_network.cmake (CTest) + e2e_gui_test.sh
packaging/            # perfil AppArmor opcional
third_party/          # libsodium, libsecp256k1, imgui (vendored/submódulos)
bip39.txt             # 2048 palabras; se embebe y se verifica por SHA-256
```

El core (`bip39_core` = todo `src/` salvo `ui/`, `clipboard/` y `security/`) es
independiente de la GUI y de OpenGL: lo comparten la app y la suite de tests.

## Modelo de amenazas (resumen)

- **Confidencialidad de la clave**: los secretos viven en páginas `mlock`'ed que se
  ponen a cero con `sodium_memzero` al destruirse; `RLIMIT_CORE=0` evita que un
  dump core escriba la frase a disco.
- **Airegap**: tres capas independientes — sin símbolos de red en el binario,
  filtro seccomp que rechaza `AF_INET`/`AF_INET6` en el kernel (los sockets
  `AF_UNIX` siguen permitidos para X11/Wayland) y, opcionalmente, AppArmor.
  Si el kernel rechaza el filtro la app **arranca igual** (fail-open) y avisa por
  stderr: pierde el refuerzo, no la función.
- **Lista de palabras**: la copia embebida se usa siempre que el `bip39.txt`
  externo no pase la comprobación de digest.
- **Ofuscación del lote**: es una capa de ofuscación con contraseña, **no**
  cifrado: sin la contraseña el XOR no es invertible. El archivo exportado
  contiene material de semilla y debe tratarse como secreto.

## Licencia

Apache-2.0 (ver `LICENSE`). Las dependencias vendored conservan sus propias
licencias: libsodium (ISC), libsecp256k1 (MIT), Dear ImGui (MIT).
