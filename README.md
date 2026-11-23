# Cipher Studio · Criptografía Clásica 3D en Rust

> **Demo en vivo (WebAssembly):** **https://ivanljprof-ai.github.io/cipher-studio-rust/**

Suite interactiva de **13 cifrados clásicos y criptoanálisis automático** escrita en **Rust 2024 puro** (sin dependencias externas), con interfaz Apple HIG en modo claro, visualizadores 3D manipulables y retos multinivel en español e inglés.

---

## Cómo se ejecuta Rust en la web

- **En GitHub Pages / Vercel (`docs/cipher.wasm`)**: Tu propio navegador (el motor WebAssembly de Safari, Chrome o Firefox) descarga `cipher.wasm` (300 KB) y ejecuta el código Rust compilado a `wasm32-unknown-unknown` **directamente en tu dispositivo**, sin servidor backend ni envío de datos fuera del navegador.
- **En local (`src/main.rs`)**: Si ejecutas el binario nativo (`cargo run --release`), el servidor HTTP multihilo en `std::net` atiende `http://127.0.0.1:8484` de forma nativa.

---

## Los 13 Cifrados Incluidos

1. **Cifrado César** (rotación + fuerza bruta 26 claves)
2. **Cifrado Atbash** (espejo `A⇄Z`)
3. **Cifrado Pigpen / Francmasón** (glifos SVG + teclado interactivo 3D)
4. **Disco de Alberti** (doble anillo 3D arrastrable con rotación polialfabética)
5. **Cifrado de Vigenère** (Índice de Coincidencia + espectro 3D)
6. **Cifrado Playfair** (matriz `5×5` 3D, trazador de dígrafos y Hill-Climbing)
7. **Cilindro de Jefferson** (tambor 3D de 36 discos con alineación de generatriz)
8. **Escítala Espartana** (vara poligonal 3D orbitable con cambio de caras)
9. **Cifrado Rail Fence** (onda zig-zag animada)
10. **Transposición por Columnas** (fuerza bruta hasta 6 columnas + columnas elevables 3D)
11. **Rejilla de Cardano** (placa 3D rotatoria `0°/90°/180°/270°` + inspector de órbitas)
12. **Tinta Invisible** (esteganografía Zero-Width `U+200B..U+FEFF` + linterna UV)
13. **Acrósticos** (generador de versos y extractor multicanal)

---

## Ejecución y Compilación Local

```bash
# Pruebas unitarias (16/16)
cargo test

# Servidor nativo local (http://127.0.0.1:8484)
cargo run --release

# Recompilar WebAssembly para GitHub Pages / Vercel
cargo build --lib --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/cifrados_rust.wasm docs/cipher.wasm
cp static/index.html docs/index.html
```
