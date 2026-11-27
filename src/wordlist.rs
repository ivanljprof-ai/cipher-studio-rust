//! Base de datos integrada de palabras, claves frecuentes y cache de sesion en Rust puro.
//!
//! Alimenta el motor de resolucion/crackeo para MD5, DES, 3DES, IDEA, AES,
//! Vigenere, Playfair, Transposicion por Columnas y Rejilla de Cardano.

use std::cell::RefCell;

thread_local! {
    static SESSION_KEYS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static SESSION_PREIMAGES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Registra una clave usada durante la sesion para auditoria/crackeo rapido.
pub fn remember_key(key: &str) {
    let k = key.trim();
    if k.is_empty() {
        return;
    }
    SESSION_KEYS.with(|cell| {
        let mut list = cell.borrow_mut();
        if !list.iter().any(|x| x == k) {
            if list.len() >= 128 {
                list.remove(0);
            }
            list.push(k.to_owned());
        }
    });
}

/// Registra un texto original hasheado/cifrado en sesion como preimagen conocida.
pub fn remember_preimage(text: &str) {
    if text.is_empty() || text.len() > 256 {
        return;
    }
    SESSION_PREIMAGES.with(|cell| {
        let mut list = cell.borrow_mut();
        if !list.iter().any(|x| x == text) {
            if list.len() >= 128 {
                list.remove(0);
            }
            list.push(text.to_owned());
        }
    });
}

/// Devuelve claves registradas en la sesion actual.
pub fn session_keys() -> Vec<String> {
    SESSION_KEYS.with(|cell| cell.borrow().clone())
}

/// Devuelve preimagenes registradas en la sesion actual.
pub fn session_preimages() -> Vec<String> {
    SESSION_PREIMAGES.with(|cell| cell.borrow().clone())
}

/// Base de datos integrada de claves frecuentes, palabras ES/EN y contrasenias comunes.
pub const WORDLIST_DB: &[&str] = &[
    // Claves y palabras clasicas de criptografia
    "CLAVE", "SECRETO", "SECRETA", "KEY", "SECRET", "PASSWORD", "MONARQUIA", "MONARCHY",
    "PLAYFAIR", "VIGENERE", "CARDANO", "ALBERTI", "JEFFERSON", "JEFFERSON1795", "MONTICELLO",
    "CESAR", "CAESAR", "ATBASH", "PIGPEN", "SCYTALE", "ESPARTA", "SPARTA", "ENIGMA",
    "CIPHER", "CRYPTO", "CODIGO", "CODE", "KEYWORD", "CLAVE123", "SECRETO1",
    "CLAVE123SECRETO1TRIPLEDS", "3DES-SECRET-KEY-24BYTES!", "PASSWORD12345678ABCDEFGH",
    "IDEA128BITSECRET", "SECRETOIDEA12345", "00010002000300040005000600070008",
    "CLAVE128BITSIDEA", "CLAVE-AES-128BIT", "SECRETO-AES-256-BITS-RUST-STUDIO",
    "CLAVE-AES-192-BITS-RUST!", "000102030405060708090A0B0C0D0E0F",
    "133457799BBCDFF1", "0123456789ABCDEF", "0123456789ABCDEFFEDCBA9876543210",
    "DESKEY01", "ADMIN123", "PASSWORD12345678",

    // Contrasenias mas frecuentes (MD5 / bloques)
    "", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "0000", "000000", "1111", "111111", "2222", "6666", "7777", "8888", "9999",
    "password", "Password", "PASSWORD", "password1", "password123", "pass", "pass123",
    "admin", "Admin", "ADMIN", "admin123", "administrator", "root", "toor", "user",
    "guest", "test", "demo", "qwerty", "qwerty123", "qwertyuiop", "asdf", "asdfgh",
    "zxcvbn", "letmein", "welcome", "monkey", "dragon", "baseball", "football", "futbol",
    "iloveyou", "sunshine", "princess", "master", "shadow", "superman", "batman",
    "starwars", "matrix", "hacker", "rust", "Rust", "RUST", "cargo", "wasm", "apple",
    "iphone", "macbook", "linux", "ubuntu", "debian", "python", "java", "javascript",
    "github", "google", "bitcoin", "crypto", "md5", "sha256", "aes", "des", "3des", "idea",
    "abc", "abc123", "abcd", "abcdef", "message digest", "hello", "Hello", "hello world",
    "Hola", "hola", "HOLA", "hola mundo", "HOLA MUNDO", "Hola Rust 2024", "hola123",
    "secreto", "secreto123", "clave", "clave123", "contrasena", "contraseña", "seguridad",
    "acceso", "usuario", "sistema", "red", "wifi", "internet", "trabajo", "escuela",

    // Vocabulario espanol frecuente (claves Vigenere/Playfair/Columnar/Cardano y preimagenes MD5)
    "ESPANA", "ESPAÑA", "MADRID", "BARCELONA", "VALENCIA", "SEVILLA", "BILBAO", "MALAGA",
    "GRANADA", "TOLEDO", "ZARAGOZA", "MURCIA", "ALICANTE", "CORDOBA", "SALAMANCA",
    "EUROPA", "AMERICA", "ROMA", "PARIS", "LONDRES", "BERLIN", "LISBOA", "FLORENCIA",
    "VENECIA", "ATENAS", "CASTILLA", "ARAGON", "ANDALUCIA", "CATALUNA", "GALICIA",
    "ATAQUE", "AMANECER", "TESORO", "MENSAJE", "CARTA", "SOBRE", "LLAVE", "PUERTA",
    "COFRE", "MAPA", "RUTA", "PUERTO", "NAVE", "BARCO", "FARO", "ISLA", "NORTE", "SUR",
    "ESTE", "OESTE", "ROBLE", "BOSQUE", "MONTE", "VALLE", "RIO", "MAR", "CIELO", "SOL",
    "LUNA", "ESTRELLA", "NOCHE", "DIA", "TARDE", "ALBA", "MEDIANOCHE", "HORA", "RELOJ",
    "TIEMPO", "ORO", "PLATA", "BRONCE", "HIERRO", "ACERO", "DIAMANTE", "PIEDRA", "TORRE",
    "MURALLA", "CASTILLO", "PALACIO", "TEMPLO", "PUENTE", "PLAZA", "BIBLIOTECA", "ARCHIVO",
    "LIBRO", "PAGINA", "VERSO", "POEMA", "LETRAS", "PALABRA", "ORDEN", "CONSEJO", "REY",
    "REINA", "CORONA", "ESPADA", "ESCUDO", "GUARDIA", "VIGIA", "CORREO", "SENAL", "SEÑAL",
    "BOVEDA", "PLANO", "PLANOS", "REUNION", "GUERRA", "PAZ", "VICTORIA", "HONOR", "FUERZA",
    "VALOR", "VERDAD", "MENTIRA", "SOMBRA", "LUZ", "FUEGO", "AGUA", "TIERRA", "AIRE",
    "VIENTO", "LLUVIA", "NIEBLA", "RAYO", "TRUENO", "LEON", "TIGRE", "AGUILA", "LOBO",
    "ZORRO", "HALCON", "OSO", "CABALLO", "PERRO", "GATO", "AVE", "SERPIENTE", "FLOR",
    "ROSA", "LIRIO", "OLIVO", "PINO", "CEDRO", "LIMON", "NARANJA", "MANZANA", "UVA",
    "CASA", "HOGAR", "FAMILIA", "AMIGO", "AMOR", "VIDA", "MUNDO", "TIERRA", "CIENCIA",
    "DATOS", "REDES", "NUBE", "SERVIDOR", "PROGRAMA", "CODIGO", "ALGORITMO", "FUNCION",
    "PRUEBA", "EJEMPLO", "NUEVO", "ANTIGUO", "GRANDE", "PEQUENO", "RAPIDO", "LENTO",
    "PRIMERO", "ULTIMO", "ALFA", "BETA", "GAMMA", "DELTA", "EPSILON", "ZETA", "THETA",
    "LAMBDA", "SIGMA", "OMEGA", "ENERO", "FEBRERO", "MARZO", "ABRIL", "MAYO", "JUNIO",
    "JULIO", "AGOSTO", "SEPTIEMBRE", "OCTUBRE", "NOVIEMBRE", "DICIEMBRE",
    "LUNES", "MARTES", "MIERCOLES", "JUEVES", "VIERNES", "SABADO", "DOMINGO",
    "ROJO", "AZUL", "VERDE", "AMARILLO", "NEGRO", "BLANCO", "GRIS", "MORADO",
    "CARLOS", "IVAN", "MARIA", "LUCIA", "PABLO", "DAVID", "JUAN", "PEPE", "ANA", "ELENA",
    "LAURA", "SARA", "JORGE", "MIGUEL", "SOFIA", "DANIEL", "ALEJANDRO", "DIEGO", "ALBERTO",

    // Vocabulario ingles frecuente
    "ATTACK", "DAWN", "TREASURE", "MESSAGE", "LETTER", "BRIDGE", "CASTLE", "TOWER",
    "KNIGHT", "KING", "QUEEN", "CROWN", "SWORD", "SHIELD", "FOREST", "MOUNTAIN", "RIVER",
    "OCEAN", "ISLAND", "NORTH", "SOUTH", "EAST", "WEST", "LIGHT", "DARK", "NIGHT",
    "MORNING", "MIDNIGHT", "GOLD", "SILVER", "DIAMOND", "STONE", "WOOD", "FIRE", "WATER",
    "EARTH", "WIND", "STORM", "THUNDER", "EAGLE", "LION", "TIGER", "WOLF", "FOX", "HAWK",
    "LEMON", "ORANGE", "ROSE", "HOUSE", "HOME", "LOVE", "LIFE", "WORLD", "TRUTH", "POWER",
    "VICTORY", "PEACE", "WAR", "TIME", "CLOCK", "BOOK", "PAGE", "NETWORK", "SERVER",
    "SYSTEM", "DATA", "CLOUD", "SECURITY", "PRIVACY", "ENCRYPT", "DECRYPT", "HASH",
    "CIPHERTEXT", "PLAINTEXT", "KEYGEN", "DEFAULT", "SUMMER", "WINTER", "SPRING", "AUTUMN",
    "JANUARY", "FEBRUARY", "MARCH", "APRIL", "JUNE", "JULY", "AUGUST", "OCTOBER", "DECEMBER",
    "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY",
    "MICHAEL", "JOHN", "ALEX", "DAVID", "SARAH", "EMILY", "JAMES", "ROBERT", "ORANGE",
    "1550", "1467", "1795", "1977", "1991", "1992", "1998", "2001", "2020", "2024", "2025", "2026",
];
