# BIP-39 Seedphrase Generator (C++)

Generador de frases semilla BIP-39 y billeteras HD para Linux, 100% airgapped.
Interfaz Dear ImGui + GLFW + OpenGL3, ~3.7k líneas propias.

Dos modos de operación:

- **Una semilla** — se muestra en pantalla, con sus direcciones EVM y BTC ya
  derivadas y botones de copia con auto-clear.
- **Lote** — genera N semillas, ofusca cada una con la contraseña que indiques y
  exporta un `.txt` (semilla obfuscada + sus direcciones) con escritura atómica.

<p align="center">
  <a href="https://github.com/disruptorh/Bip39-Generator-C-/releases/latest/download/bip39_generator">
    <img alt="Descargar" src="https://img.shields.io/badge/%E2%AC%87%20Download-latest%20release-2f6feb?style=for-the-badge&logo=github&logoColor=white">
  </a>
  <a href="https://github.com/disruptorh/Bip39-Generator-C-/releases/latest">
    <img alt="Versiones" src="https://img.shields.io/github/v/release/disruptorh/Bip39-Generator-C-?label=release&style=flat&logo=github&logoColor=white">
  </a>
  <a href="./LICENSE">
    <img alt="Licencia" src="https://img.shields.io/badge/licencia-Apache--2.0-blue?style=flat">
  </a>
</p>

## 📥 Descarga rápida

El botón de arriba descarga el asset `bip39_generator` de la release más reciente
publicada: un ejecutable **Linux x86-64 sin extensión de fichero**. Es un único
binario, no un instalador ni un `.tar.gz`.

Para usarlo desde una terminal, o para fijarte en una versión concreta:

```bash
curl -L -o bip39_generator https://github.com/disruptorh/Bip39-Generator-C-/releases/latest/download/bip39_generator && chmod +x bip39_generator && ./bip39_generator
```

No es un binario estático: enlaza dinámicamente contra `libOpenGL.so.0`,
`libglfw.so.3` y `libX11.so.6`. En Debian/Ubuntu se resuelven con:

```bash
sudo apt update && sudo apt install -y libopengl-dev libglfw3-dev libx11-dev libgl1
```

Para ejecutarlo sin pantalla (CI, contenedores, SSH sin X11):

```bash
sudo apt install -y xvfb && xvfb-run -a ./bip39_generator
```

## 🚀 Uso rápido

1. Elige el modo (una semilla o varias) y la longitud (12 o 24 palabras).
2. Opcionalmente escribe entropía adicional: se mezcla con la del SO mediante
   HKDF-SHA512, así que nunca *reemplaza* la entropía del sistema. El medidor
   muestra los Bits estimados (estimación heurística de Shannon, no una garantía
   criptográfica; el suelo garantizado es el CSPRNG del sistema).
3. En modo **una semilla**, las direcciones se derivan de la frase ya revelada:
   - EVM: `m/44'/60'/0'/0/0` (checksum EIP-55)
   - BTC: `m/84'/0'/0'/0/0` (SegWit nativo P2WPKH, bech32)

   El portapapeles se auto-limpia a los 30 s (configurable con la variable de
   entorno `BIP39_CLIPBOARD_TIMEOUT_MS`, en milisegundos).
4. En modo **lote**, cada semilla se ofusca con XOR de una clave derivada por
   PBKDF2-HMAC-SHA256 (KDF v1, compatible con la app BIP-39 Obfuscator) y se
   escribe con `O_EXCL` + renombrado atómico, avisando si el archivo existe.

## 📦 Compilar desde código

### Requisitos

- CMake ≥ 3.20, compilador C++20 (GCC ≥ 10 o clang ≥ 12), pkg-config, make.
- Submódulos de Git inicializados (obligatorio: sin ellos el configure falla).
- Sistema: development headers de GLFW3, X11 y OpenGL.

### Clonar

Este repo **usa submódulos**. Los dos (`third_party/imgui` y
`third_party/libsodium`) se inicializan con `--init --recursive`:

```bash
# 1. Clonar el repositorio con sus submódulos
git clone --recurse-submodules https://github.com/disruptorh/Bip39-Generator-C-.git
cd Bip39-Generator-C--
```

Si ya lo clonaste sin ellos, o los tienes a medias:

```bash
# 2. Inicializar los submódulos (imprescindible antes de configurar)
git submodule update --init --recursive
```

### Dependencias

**Ya vendored, no hay que instalarlas** (el build no descarga nada de la red):

| Dependencia | Dónde vive | Nota |
|---|---|---|
| Dear ImGui | `third_party/imgui` | submódulo, parcheado para el perfil airgapped |
| libsodium 1.0.22 | `third_party/libsodium` | submódulo; se compila estático vía autotools (`ExternalProject`) |
| libsecp256k1 | `third_party/libsecp256k1` | **versionada en el propio repo**, no es submódulo; compilación mínima sin módulos opcionales |

**Hay que instalarlas del sistema** (son las que pide el `CMakeLists.txt` vía
`find_package(OpenGL)` y `pkg_check_modules(glfw3, x11)`):

| Paquete Debian/Ubuntu | Para qué lo pide CMake |
|---|---|
| `build-essential` | g++, make |
| `cmake` | el propio build |
| `pkg-config` | `pkg_check_modules` |
| `libglfw3-dev` | `glfw3` (ventana, contexto GL, portapapeles) |
| `libx11-dev` | `x11` (portapapeles y display) |
| `libopengl-dev` | `find_package(OpenGL)` → `OpenGL::GL` |
| `libgl-dev` | cabeceras y `libGL.so` de Mesa |

```bash
# 3. Instalar las dependencias de compilación (Debian/Ubuntu)
sudo apt update && sudo apt install -y build-essential cmake pkg-config libglfw3-dev libx11-dev libopengl-dev libgl-dev
```

### Compilar

```bash
# 4. Configurar y compilar
cmake -S . -B build && cmake --build build -j
```

El ejecutable queda **directamente en `build/`**: `./build/bip39_generator`.
Nada de `build/Release/`.

La primera build tarda bastante más que las siguientes: libsodium se compila con
autotools y libsecp256k1 también, como `ExternalProject` y `add_subdirectory`
respectivamente.

### Ejecutar los tests

```bash
# 5. Suite de tests (requiere el binario ya compilado)
ctest --test-dir build --output-on-failure
```

| Target CTest | Qué cubre |
|---|---|
| `bip39_tests` | Vectores BIP-39 oficiales, wordlist + digest SHA-256, mezclador de entropía, buffers seguros, direcciones EVM/BTC, export por lotes |
| `clipboard_x11` | Portapapeles X11 real (se salta solo si no hay display) |
| `no_network_symbols` | `nm -D` sobre el binario: ninguna tabla dinámica con símbolos de red/DNS/shell/`dlopen` |

Los tres los registra `BIP39_BUILD_TESTS` (por defecto `ON`).

### Ejecutar la aplicación

```bash
# 6. Lanzar la GUI
./build/bip39_generator
```

La app usa `mlock` para fijar el material sensible en RAM. Si el límite de
memoria bloqueada es bajo, los buffers no se pueden fijar: el ruido viene de
`ulimit -l`. Se recomienda devolverlo a `unlimited` en tu shell antes de lanzar
la app:

```bash
# 7. Recomendado: sin límite de memoria bloqueada
ulimit -l unlimited && ./build/bip39_generator
```

## 🧰 Comandos útiles / Opciones

Opciones de CMake:

| Opción | Por defecto | Qué hace |
|---|---|---|
| `BIP39_BUILD_TESTS` | `ON` | Compila `bip39_tests`, `bip39_clipboard_test` y registra los tests de CTest |
| `CMAKE_BUILD_TYPE` | `Release` | Se fuerza a `Release` si no lo pasas |

```bash
# Build sin suite de tests (más rápido)
cmake -S . -B build -DBIP39_BUILD_TESTS=OFF && cmake --build build -j
```

Variables de entorno que la app lee:

| Variable | Por defecto | Efecto |
|---|---|---|
| `BIP39_CLIPBOARD_TIMEOUT_MS` | `30000` | Milisegundos hasta el auto-clear del portapapeles |

### Test end-to-end de la GUI

Hay un script que conduce la app con teclado sobre un display Xvfb aislado y
verifica cada botón de copia contra la selección CLIPBOARD, el auto-clear, que no
se persiste nada bajo `$HOME` y el export por lotes (6 semillas ofuscadas con sus
direcciones EVM y BTC).

Necesita tres herramientas que **no** son dependencias de compilación:

```bash
# Instalar las herramientas del e2e de GUI (Debian/Ubuntu)
sudo apt update && sudo apt install -y xvfb xdotool xclip
```

```bash
# Ejecutar el e2e de la GUI (desde la raíz del repo, con la app ya compilada)
mkdir -p /tmp/opencode && scripts/e2e_gui_test.sh
```

El `mkdir -p /tmp/opencode` no es opcional: el script redirige sus logs a rutas
fijas bajo `/tmp/opencode/` (`e2e_app.log`, `e2e_xvfb.log`) y sin ese directorio
el display virtual no arranca.

## 🗂️ Estructura del proyecto

```text
.
├── CMakeLists.txt          # targets, vendored, guardas de CTest
├── bip39.txt               # 2048 palabras; se embeben y se verifican por SHA-256
├── packaging/
│   └── bip39_generator.apparmor   # perfil AppArmor opcional (deny network)
├── scripts/
│   ├── check_no_network.cmake     # guardia de CTest: nm -D sobre el binario
│   └── e2e_gui_test.sh            # e2e de GUI con Xvfb + xdotool + xclip
├── src/
│   ├── main.cpp            # init GLFW/ImGui + hardening de runtime
│   ├── secure_mem/         # buffers mlock'ed, secure_string, secure_buffer
│   ├── entropy/            # random_bytes (libsodium) + HKDF mix + estimador
│   ├── bip39/              # wordlist (con digest) y entropy_to_mnemonic
│   ├── crypto/             # keccak256, ripemd160, base58, pbkdf2, kdf, seed_transformer
│   ├── bip32/              # derivación HD (master + derive_path + fingerprint)
│   ├── address/            # evm.cpp, btc.cpp, bech32, addresses (orquestador)
│   ├── export/             # batch_export: render del .txt + escritura atómica
│   ├── clipboard/          # portapapeles X11 con auto-clear
│   ├── security/           # seccomp-BPF (bloquea sockets de red)
│   └── ui/                 # app (estado) + pantallas config/reveal/batch
├── tests/                  # suite propia + vectores BIP-39 + test de portapapeles
└── third_party/            # imgui y libsodium (submódulos) + libsecp256k1 (in-tree)
```

El core (`bip39_core` = todo `src/` salvo `ui/`, `clipboard/` y `security/`) es
independiente de la GUI y de OpenGL: lo comparten la app y la suite de tests.

## 🔐 Seguridad

### Modelo de amenazas (resumen)

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

### Activar el perfil AppArmor (opcional)

El perfil está en `packaging/bip39_generator.apparmor` y deniega toda la red
(`deny network`), además de restringir el acceso a ficheros. Asume el binario
instalado en `/usr/local/bin/bip39_generator`. Cópialo e instálalo así:

```bash
# Instalar el binario donde lo espera el perfil y activar AppArmor
sudo install -m 755 build/bip39_generator /usr/local/bin/bip39_generator && sudo install -m 644 packaging/bip39_generator.apparmor /etc/apparmor.d/bip39_generator && sudo apparmor_parser -r /etc/apparmor.d/bip39_generator
```

Para quitarlo:

```bash
# Quitar el perfil
sudo apparmor_parser -R /etc/apparmor.d/bip39_generator && sudo rm -f /etc/apparmor.d/bip39_generator
```

### Endurecimiento de compilación

El `CMakeLists.txt` aplica a todos los targets: `-Wall -Wextra -Wpedantic
-fstack-protector-strong`, `_FORTIFY_SOURCE=2` y las opciones de enlace
`-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`. Dear ImGui se compila con
`IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS` (elimina el "open in shell" con
`fork`/`execvp`) y su loader de OpenGL resuelve los entry points con
`glfwGetProcAddress()` en vez de `dlopen()`.

### Sin escritura automática a disco

Ni estado de ventana de ImGui (`IniFilename = nullptr`), ni caches de shaders de
OpenGL, ni core dumps. El único archivo que se crea es el `.txt` de exportación
que el usuario nombra explícitamente.

## 📄 Licencia

Apache-2.0 (ver `LICENSE`). Las dependencias vendored conservan sus propias
licencias: libsodium 1.0.22 (ISC), libsecp256k1 (MIT), Dear ImGui (MIT).