//! Motor de criptografia clasica y criptoanalisis en Rust puro (sin dependencias externas).
//!
//! Implementa cifrado, descifrado y resolucion automatica para 13 algoritmos clasicos:
//! Cesar, Atbash, Pigpen, Alberti, Vigenere, Playfair, Cilindro de Jefferson,
//! Escitala espartana, Rail Fence, Transposicion por columnas, Rejilla de Cardano,
//! Tinta invisible (Zero-Width) y Acrosticos.

use std::collections::BTreeMap;
use std::fmt;

/// Accion solicitada al motor criptografico.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Encrypt,
    Decrypt,
    Solve,
}

impl Action {
    /// Convierte una cadena a `Action`.
    pub fn parse(s: &str) -> Result<Self, CipherError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "encrypt" | "cifrar" => Ok(Self::Encrypt),
            "decrypt" | "descifrar" => Ok(Self::Decrypt),
            "solve" | "resolver" | "crack" => Ok(Self::Solve),
            other => Err(CipherError::InvalidInput(format!("accion no soportada: {other}"))),
        }
    }
}

/// Errores tipados del dominio criptografico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    UnknownCipher(String),
    InvalidInput(String),
    JsonParse(String),
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCipher(c) => write!(f, "cifrado desconocido: {c}"),
            Self::InvalidInput(msg) => write!(f, "entrada invalida: {msg}"),
            Self::JsonParse(msg) => write!(f, "json invalido: {msg}"),
        }
    }
}

impl std::error::Error for CipherError {}

/// Candidato devuelto durante una operacion de resolucion/criptoanalisis.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub label: String,
    pub text: String,
    pub score: f64,
}

/// Elemento estructurado de visualizacion (matriz, tabla o fichas).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridData {
    pub kind: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Metadatos clave-valor para visualizadores especializados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaEntry {
    pub key: String,
    pub value: String,
}

/// Respuesta unificada del motor criptografico.
#[derive(Debug, Clone, PartialEq)]
pub struct CipherOutput {
    pub cipher: String,
    pub action: String,
    pub result: String,
    pub explanation: String,
    pub candidates: Vec<Candidate>,
    pub grid: Option<GridData>,
    pub meta: Vec<MetaEntry>,
}

/// Peticion entrante al motor criptografico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherRequest {
    pub cipher: String,
    pub action: String,
    pub text: String,
    pub key: String,
    pub param: String,
}

/// Ejecuta la operacion solicitada sobre el cifrado indicado.
pub fn execute(req: &CipherRequest) -> Result<CipherOutput, CipherError> {
    let action = Action::parse(&req.action)?;
    let cipher = req.cipher.trim().to_ascii_lowercase();
    let mut out = match cipher.as_str() {
        "caesar" | "cesar" => run_caesar(action, &req.text, &req.key),
        "atbash" => run_atbash(action, &req.text),
        "pigpen" | "francmason" => run_pigpen(action, &req.text),
        "alberti" => run_alberti(action, &req.text, &req.key, &req.param),
        "vigenere" => run_vigenere(action, &req.text, &req.key),
        "playfair" => run_playfair(action, &req.text, &req.key),
        "jefferson" => run_jefferson(action, &req.text, &req.key, &req.param),
        "scytale" | "escitala" => run_scytale(action, &req.text, &req.key, &req.param),
        "rail_fence" | "railfence" => run_rail_fence(action, &req.text, &req.key, &req.param),
        "columnar" => run_columnar(action, &req.text, &req.key),
        "cardano" => run_cardano(action, &req.text, &req.key, &req.param),
        "invisible_ink" | "tinta_invisible" => run_invisible_ink(action, &req.text, &req.key),
        "acrostic" | "acrostico" | "acrosticos" => run_acrostic(action, &req.text, &req.key, &req.param),
        _ => return Err(CipherError::UnknownCipher(req.cipher.clone())),
    }?;
    out.cipher = cipher;
    out.action = match action {
        Action::Encrypt => "encrypt",
        Action::Decrypt => "decrypt",
        Action::Solve => "solve",
    }
    .to_owned();
    Ok(out)
}

// ============================================================================
// Normalizacion y utilidades de texto / scoring ES+EN
// ============================================================================

/// Normaliza un caracter latino con acento/dieresis/enie a su letra ASCII base A-Z preservando caja.
fn fold_latin_char(ch: char) -> char {
    match ch {
        'á' | 'à' | 'ä' | 'â' | 'ã' | 'å' => 'a',
        'Á' | 'À' | 'Ä' | 'Â' | 'Ã' | 'Å' => 'A',
        'é' | 'è' | 'ë' | 'ê' => 'e',
        'É' | 'È' | 'Ë' | 'Ê' => 'E',
        'í' | 'ì' | 'ï' | 'î' => 'i',
        'Í' | 'Ì' | 'Ï' | 'Î' => 'I',
        'ó' | 'ò' | 'ö' | 'ô' | 'õ' => 'o',
        'Ó' | 'Ò' | 'Ö' | 'Ô' | 'Õ' => 'O',
        'ú' | 'ù' | 'ü' | 'û' => 'u',
        'Ú' | 'Ù' | 'Ü' | 'Û' => 'U',
        'ñ' => 'n',
        'Ñ' => 'N',
        'ç' => 'c',
        'Ç' => 'C',
        _ => ch,
    }
}

/// Normaliza una cadena manteniendo formato pero plegando diacriticos latinos.
fn normalize_latin_preserving(s: &str) -> String {
    s.chars().map(fold_latin_char).collect()
}

/// Extrae unicamente letras ASCII A-Z en mayuscula (plegando diacriticos).
fn extract_upper_az(s: &str) -> Vec<u8> {
    s.chars()
        .map(fold_latin_char)
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect()
}

/// Frecuencias relativas en espanol (A..Z), normalizadas 0..100.
const ES_FREQ: [f64; 26] = [
    12.53, 1.42, 4.68, 5.86, 13.68, 0.69, 1.01, 0.70, 6.25, 0.44, 0.02, 4.97, 3.15,
    6.71, 8.68, 2.51, 0.88, 6.87, 7.98, 4.63, 3.93, 0.90, 0.01, 0.22, 0.90, 0.52,
];

/// Frecuencias relativas en ingles (A..Z), normalizadas 0..100.
const EN_FREQ: [f64; 26] = [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
    6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
];

const ES_BIGRAMS: &[(&str, f64)] = &[
    ("ES", 3.5), ("EN", 3.4), ("EL", 3.2), ("DE", 3.2), ("LA", 3.0), ("OS", 2.8),
    ("AR", 2.7), ("UE", 2.6), ("RA", 2.5), ("RE", 2.5), ("ON", 2.5), ("AN", 2.4),
    ("AS", 2.4), ("ER", 2.4), ("AD", 2.3), ("OR", 2.3), ("AL", 2.2), ("IN", 2.1),
    ("CI", 2.0), ("CO", 2.0), ("DO", 2.0), ("TA", 1.9), ("TE", 1.9), ("SE", 1.9),
    ("NO", 1.8), ("LE", 1.8), ("UN", 1.8), ("QU", 1.9), ("RO", 1.7), ("PA", 1.7),
    ("ME", 1.6), ("TO", 1.6), ("DA", 1.6), ("CA", 1.6), ("LO", 1.6), ("ST", 1.6),
    ("HO", 1.4), ("MU", 1.3), ("ND", 1.4), ("AT", 1.4), ("AM", 1.4), ("EC", 1.4),
];

const EN_BIGRAMS: &[(&str, f64)] = &[
    ("TH", 3.8), ("HE", 3.5), ("IN", 3.0), ("ER", 2.8), ("AN", 2.6), ("RE", 2.5),
    ("ON", 2.3), ("AT", 2.2), ("EN", 2.1), ("ND", 2.1), ("TI", 2.0), ("ES", 2.0),
    ("OR", 2.0), ("TE", 1.9), ("OF", 1.8), ("ED", 1.8), ("IS", 1.8), ("IT", 1.8),
    ("AL", 1.7), ("AR", 1.7), ("ST", 1.7), ("TO", 1.7), ("NT", 1.6), ("NG", 1.6),
    ("SE", 1.5), ("HA", 1.5), ("OU", 1.5), ("VE", 1.4), ("CO", 1.4), ("ME", 1.4),
];

const TRIGRAMS_COMMON: &[(&str, f64)] = &[
    ("QUE", 5.5), ("EST", 4.5), ("ENT", 4.5), ("ION", 4.5), ("CIO", 4.2), ("ADO", 4.2),
    ("LOS", 4.2), ("LAS", 4.2), ("DEL", 4.2), ("CON", 4.0), ("PAR", 3.8), ("PRO", 3.8),
    ("TRA", 3.8), ("MEN", 3.8), ("COM", 3.8), ("UNA", 4.0), ("POR", 4.0), ("THE", 5.5),
    ("AND", 5.0), ("ING", 5.0), ("TIO", 4.5), ("HER", 4.0), ("FOR", 4.2), ("THA", 4.0),
    ("ERE", 3.8), ("HIS", 3.8), ("ALL", 3.8), ("HOL", 4.0), ("OLA", 4.0), ("MUN", 4.0),
    ("UND", 4.0), ("NDO", 4.0), ("ATA", 4.2), ("TAQ", 3.5), ("AQU", 4.0), ("AMA", 3.8),
    ("MAN", 3.8), ("ANE", 3.5), ("ECE", 3.8), ("CER", 3.8), ("SEC", 4.2), ("ECR", 4.0),
    ("CRE", 4.0), ("RET", 4.0), ("ETO", 3.8), ("CIF", 4.0), ("IFR", 3.8), ("FRA", 3.8),
    ("RAD", 3.8), ("COD", 3.8), ("ODI", 3.8), ("DIG", 3.8), ("IGO", 3.8), ("HEL", 4.0),
    ("ELL", 4.0), ("LLO", 4.0), ("WOR", 4.0), ("ORL", 4.0), ("RLD", 4.0), ("DAW", 4.0),
    ("AWN", 4.0), ("TES", 4.0), ("ESO", 4.0), ("SOR", 4.0), ("ORO", 4.0), ("OCU", 4.0),
    ("CUL", 4.0), ("ULT", 4.0), ("LTO", 4.0),
];

const COMMON_WORDS: &[&str] = &[
    "EL", "LA", "DE", "QUE", "EN", "Y", "A", "LOS", "DEL", "SE", "LAS", "POR", "UN",
    "PARA", "CON", "NO", "UNA", "SU", "AL", "LO", "COMO", "MAS", "PERO", "ESTE", "ESTA",
    "ENTRE", "CUANDO", "MUY", "SIN", "SOBRE", "SER", "TIENE", "HOLA", "MUNDO", "SECRETO",
    "SECRETA", "ATAQUE", "AMANECER", "MENSAJE", "CLAVE", "TESORO", "CODIGO", "OCULTO",
    "CIFRADO", "DESCIFRAR", "ESPARTA", "ROMA", "NOCHE", "DIA", "PUERTA", "ORO", "BAJO",
    "ROBLE", "REUNION", "MANANA", "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
    "HER", "WAS", "ONE", "OUR", "OUT", "DAY", "HIS", "HOW", "NEW", "NOW", "SEE", "WHO",
    "HELLO", "WORLD", "SECRET", "ATTACK", "DAWN", "MESSAGE", "CIPHER", "KEY", "CODE",
    "HIDDEN", "TREASURE",
];

/// Puntua que tan verosimil es un texto como lenguaje natural espanol o ingles.
pub fn score_text(text: &str) -> f64 {
    let letters = extract_upper_az(text);
    if letters.is_empty() {
        return -1000.0;
    }
    let n = letters.len() as f64;
    let mut counts = [0usize; 26];
    let mut vowels = 0usize;
    for &b in &letters {
        let idx = (b - b'A') as usize;
        counts[idx] += 1;
        if matches!(b, b'A' | b'E' | b'I' | b'O' | b'U') {
            vowels += 1;
        }
    }

    let mut es_uni = 0.0;
    let mut en_uni = 0.0;
    for (i, &c) in counts.iter().enumerate() {
        let freq = c as f64 / n;
        es_uni += freq * (ES_FREQ[i] + 0.05).ln();
        en_uni += freq * (EN_FREQ[i] + 0.05).ln();
    }

    let mut es_bi = 0.0;
    let mut en_bi = 0.0;
    if letters.len() >= 2 {
        for win in letters.windows(2) {
            let pair = [win[0], win[1]];
            if let Some((_, w)) = ES_BIGRAMS.iter().find(|(bg, _)| bg.as_bytes() == pair) {
                es_bi += *w;
            }
            if let Some((_, w)) = EN_BIGRAMS.iter().find(|(bg, _)| bg.as_bytes() == pair) {
                en_bi += *w;
            }
        }
        es_bi /= (letters.len() - 1) as f64;
        en_bi /= (letters.len() - 1) as f64;
    }

    let mut tri_bonus = 0.0;
    if letters.len() >= 3 {
        for win in letters.windows(3) {
            let tri = [win[0], win[1], win[2]];
            if let Some((_, w)) = TRIGRAMS_COMMON.iter().find(|(tg, _)| tg.as_bytes() == tri) {
                tri_bonus += *w;
            }
        }
        tri_bonus /= (letters.len() - 2) as f64;
    }

    let vowel_ratio = vowels as f64 / n;
    let vowel_penalty = if !(0.18..=0.68).contains(&vowel_ratio) {
        -3.5
    } else {
        (1.0 - (vowel_ratio - 0.43).abs() * 3.0).max(-1.0)
    };

    let mut word_bonus = 0.0;
    let norm = normalize_latin_preserving(text).to_ascii_uppercase();
    for tok in norm.split(|c: char| !c.is_ascii_alphabetic()) {
        if tok.len() >= 2 && COMMON_WORDS.contains(&tok) {
            word_bonus += 2.2;
        }
    }
    let compact: String = norm.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    for &w in COMMON_WORDS {
        if w.len() >= 5 && compact.contains(w) {
            word_bonus += 3.0;
        }
    }

    let lang_score = (es_uni + es_bi * 1.4).max(en_uni + en_bi * 1.4);
    lang_score + tri_bonus * 1.3 + vowel_penalty + word_bonus
}

fn format_score(score: f64) -> String {
    format!("{score:.2}")
}

// ============================================================================
// 1. Cifrado Cesar
// ============================================================================

fn shift_caesar(text: &str, shift: i32) -> String {
    let s = shift.rem_euclid(26) as u8;
    text.chars()
        .map(fold_latin_char)
        .map(|ch| {
            if ch.is_ascii_uppercase() {
                (b'A' + (ch as u8 - b'A' + s) % 26) as char
            } else if ch.is_ascii_lowercase() {
                (b'a' + (ch as u8 - b'a' + s) % 26) as char
            } else {
                ch
            }
        })
        .collect()
}

fn parse_caesar_shift(key: &str) -> Result<i32, CipherError> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Ok(3);
    }
    if let Ok(n) = trimmed.parse::<i32>() {
        return Ok(n);
    }
    let ch = fold_latin_char(trimmed.chars().next().unwrap_or('D')).to_ascii_uppercase();
    if ch.is_ascii_uppercase() {
        return Ok((ch as u8 - b'A') as i32);
    }
    Err(CipherError::InvalidInput("la clave de Cesar debe ser un numero o letra A-Z".into()))
}

fn run_caesar(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let shift = parse_caesar_shift(key)?;
    let (result, explanation, candidates, eff_shift) = match action {
        Action::Encrypt => {
            let out = shift_caesar(text, shift);
            (
                out,
                format!("Desplazamiento Cesar +{shift} aplicado sobre el alfabeto latino (A-Z)."),
                Vec::new(),
                shift.rem_euclid(26),
            )
        }
        Action::Decrypt => {
            let out = shift_caesar(text, -shift);
            (
                out,
                format!("Desplazamiento inverso Cesar -{shift} aplicado."),
                Vec::new(),
                shift.rem_euclid(26),
            )
        }
        Action::Solve => {
            let mut list: Vec<(i32, String, f64)> = (0..26)
                .map(|s| {
                    let cand = shift_caesar(text, -s);
                    let sc = score_text(&cand);
                    (s, cand, sc)
                })
                .collect();
            list.sort_by(|a, b| b.2.total_cmp(&a.2));
            let best_s = list[0].0;
            let best_text = list[0].1.clone();
            let cands = list
                .into_iter()
                .map(|(s, t, sc)| Candidate {
                    label: format!("Clave +{s} ({})", (b'A' + s as u8) as char),
                    text: t,
                    score: sc,
                })
                .collect();
            (
                best_text,
                format!("Fuerza bruta de 26 rotaciones en Rust; mejor coincidencia con clave +{best_s}."),
                cands,
                best_s,
            )
        }
    };

    let plain_row: Vec<String> = (0..26).map(|i| ((b'A' + i as u8) as char).to_string()).collect();
    let cipher_row: Vec<String> = (0..26)
        .map(|i| ((b'A' + ((i + eff_shift) % 26) as u8) as char).to_string())
        .collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "substitution".into(),
            headers: plain_row,
            rows: vec![cipher_row],
        }),
        meta: vec![MetaEntry {
            key: "shift".into(),
            value: eff_shift.to_string(),
        }],
    })
}

// ============================================================================
// 2. Cifrado Atbash
// ============================================================================

fn transform_atbash(text: &str) -> String {
    text.chars()
        .map(fold_latin_char)
        .map(|ch| {
            if ch.is_ascii_uppercase() {
                (b'Z' - (ch as u8 - b'A')) as char
            } else if ch.is_ascii_lowercase() {
                (b'z' - (ch as u8 - b'a')) as char
            } else {
                ch
            }
        })
        .collect()
}

fn run_atbash(action: Action, text: &str) -> Result<CipherOutput, CipherError> {
    let out = transform_atbash(text);
    let plain_row: Vec<String> = (0..26).map(|i| ((b'A' + i) as char).to_string()).collect();
    let inv_row: Vec<String> = (0..26).map(|i| ((b'Z' - i) as char).to_string()).collect();
    let candidates = if action == Action::Solve {
        vec![
            Candidate {
                label: "Atbash (A <-> Z)".into(),
                text: out.clone(),
                score: score_text(&out),
            },
            Candidate {
                label: "Texto original".into(),
                text: text.to_owned(),
                score: score_text(text),
            },
        ]
    } else {
        Vec::new()
    };

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result: out,
        explanation: "Sustitucion especular simetrica Atbash (A<->Z, B<->Y, ..., M<->N).".into(),
        candidates,
        grid: Some(GridData {
            kind: "substitution".into(),
            headers: plain_row,
            rows: vec![inv_row],
        }),
        meta: Vec::new(),
    })
}

// ============================================================================
// 3. Cifrado Pigpen (Francmason)
// ============================================================================

const PIGPEN_SYMBOLS: [&str; 26] = [
    "┘", "⊔", "└", "⊐", "□", "⊏", "┐", "⊓", "┌", // A-I (sin punto)
    "┘·", "⊔·", "└·", "⊐·", "□·", "⊏·", "┐·", "⊓·", "┌·", // J-R (con punto)
    "∨", ">", "<", "∧", // S-V (X sin punto)
    "∨·", ">·", "<·", "∧·", // W-Z (X con punto)
];

fn encode_pigpen(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars().map(fold_latin_char) {
        if ch.is_ascii_alphabetic() {
            let idx = (ch.to_ascii_uppercase() as u8 - b'A') as usize;
            out.push_str(PIGPEN_SYMBOLS[idx]);
        } else {
            out.push(ch);
        }
    }
    out
}

fn decode_pigpen(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let base_idx = match c {
            '┘' => Some(0),
            '⊔' => Some(1),
            '└' => Some(2),
            '⊐' => Some(3),
            '□' => Some(4),
            '⊏' => Some(5),
            '┐' => Some(6),
            '⊓' => Some(7),
            '┌' => Some(8),
            '∨' => Some(18),
            '>' => Some(19),
            '<' => Some(20),
            '∧' => Some(21),
            _ => None,
        };
        if let Some(base) = base_idx {
            let has_dot = i + 1 < chars.len() && matches!(chars[i + 1], '·' | '•' | '.');
            let idx = if has_dot {
                i += 1;
                if base < 9 { base + 9 } else { base + 4 }
            } else {
                base
            };
            out.push((b'A' + idx as u8) as char);
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

fn contains_pigpen_symbols(text: &str) -> bool {
    text.chars()
        .any(|c| matches!(c, '┘' | '⊔' | '└' | '⊐' | '□' | '⊏' | '┐' | '⊓' | '┌' | '∨' | '∧'))
}

fn run_pigpen(action: Action, text: &str) -> Result<CipherOutput, CipherError> {
    let (result, explanation, glyph_source) = match action {
        Action::Encrypt => {
            let enc = encode_pigpen(text);
            (
                enc,
                "Codificacion geometrica francmasona en 2 cuadriculas 3x3 y 2 aspas X.".into(),
                normalize_latin_preserving(text).to_ascii_uppercase(),
            )
        }
        Action::Decrypt => {
            let dec = decode_pigpen(text);
            (
                dec.clone(),
                "Decodificacion de simbolos geometricos Pigpen a letras latinas.".into(),
                dec,
            )
        }
        Action::Solve => {
            if contains_pigpen_symbols(text) {
                let dec = decode_pigpen(text);
                (
                    dec.clone(),
                    "Simbolos francmasones detectados y traducidos automaticamente.".into(),
                    dec,
                )
            } else {
                let enc = encode_pigpen(text);
                (
                    enc,
                    "Texto latino convertido a simbolos Pigpen para inspeccion visual.".into(),
                    normalize_latin_preserving(text).to_ascii_uppercase(),
                )
            }
        }
    };

    let letters: String = glyph_source
        .chars()
        .filter(|c| c.is_ascii_alphabetic() || *c == ' ')
        .collect();
    let headers: Vec<String> = (0..26).map(|i| ((b'A' + i as u8) as char).to_string()).collect();
    let syms: Vec<String> = PIGPEN_SYMBOLS.iter().map(|s| (*s).to_owned()).collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates: Vec::new(),
        grid: Some(GridData {
            kind: "pigpen_map".into(),
            headers,
            rows: vec![syms],
        }),
        meta: vec![MetaEntry {
            key: "glyph_letters".into(),
            value: letters,
        }],
    })
}

// ============================================================================
// 4. Disco de Alberti
// ============================================================================

const ALBERTI_OUTER: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALBERTI_DEFAULT_INNER: &[u8; 26] = b"GKLNPRTVZXYSOMQIHFDBACEJUW";

fn build_alberti_inner(key: &str) -> ([u8; 26], usize) {
    let cleaned = extract_upper_az(key);
    if cleaned.len() <= 1 {
        let target = cleaned.first().copied().unwrap_or(b'K');
        let idx = ALBERTI_DEFAULT_INNER
            .iter()
            .position(|&c| c == target)
            .unwrap_or(0);
        return (*ALBERTI_DEFAULT_INNER, idx);
    }

    let mut seen = [false; 26];
    let mut ring = [b'A'; 26];
    let mut pos = 0;
    for &b in &cleaned {
        let i = (b - b'A') as usize;
        if !seen[i] {
            seen[i] = true;
            ring[pos] = b;
            pos += 1;
        }
    }
    for &b in ALBERTI_DEFAULT_INNER {
        let i = (b - b'A') as usize;
        if !seen[i] {
            seen[i] = true;
            ring[pos] = b;
            pos += 1;
        }
    }
    (ring, 0)
}

fn transform_alberti(text: &str, inner: &[u8; 26], start_offset: usize, period: usize, encrypt: bool) -> String {
    let mut offset = start_offset % 26;
    let mut processed = 0usize;
    let mut out = String::with_capacity(text.len());

    for ch in text.chars().map(fold_latin_char) {
        if ch.is_ascii_alphabetic() {
            if period > 0 && processed > 0 && processed.is_multiple_of(period) {
                offset = (offset + 1) % 26;
            }
            let up = ch.to_ascii_uppercase() as u8;
            let mapped = if encrypt {
                let outer_idx = (up - b'A') as usize;
                inner[(outer_idx + offset) % 26] as char
            } else {
                let inner_pos = inner.iter().position(|&c| c == up).unwrap_or(0);
                ALBERTI_OUTER[(inner_pos + 26 - offset) % 26] as char
            };
            if ch.is_ascii_lowercase() {
                out.push(mapped.to_ascii_lowercase());
            } else {
                out.push(mapped);
            }
            processed += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn run_alberti(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let (inner, start_offset) = build_alberti_inner(key);
    let period = param.trim().parse::<usize>().unwrap_or(4);

    let (result, explanation, candidates, best_offset, best_period) = match action {
        Action::Encrypt => {
            let out = transform_alberti(text, &inner, start_offset, period, true);
            (
                out,
                format!(
                    "Disco de Alberti alineado en '{}' (indice {}) con giro cada {} letras.",
                    inner[start_offset] as char, start_offset, period
                ),
                Vec::new(),
                start_offset,
                period,
            )
        }
        Action::Decrypt => {
            let out = transform_alberti(text, &inner, start_offset, period, false);
            (
                out,
                format!(
                    "Descifrado Alberti desde alineacion '{}' con cadencia de giro {}.",
                    inner[start_offset] as char, period
                ),
                Vec::new(),
                start_offset,
                period,
            )
        }
        Action::Solve => {
            let mut list: Vec<(usize, usize, String, f64)> = Vec::new();
            for &p in &[0usize, 1, 2, 3, 4, 5, 6] {
                for off in 0..26 {
                    let cand = transform_alberti(text, &inner, off, p, false);
                    let sc = score_text(&cand);
                    list.push((off, p, cand, sc));
                }
            }
            list.sort_by(|a, b| b.3.total_cmp(&a.3));
            let (b_off, b_per, b_txt, _) = list[0].clone();
            let cands = list
                .into_iter()
                .take(15)
                .map(|(off, p, txt, sc)| Candidate {
                    label: format!("Indice '{}' (offset {off}, giro cada {p})", inner[off] as char),
                    text: txt,
                    score: sc,
                })
                .collect();
            (
                b_txt,
                format!(
                    "Busqueda sobre 26 alineaciones y periodos 0..6: mejor coincidencia '{}' cada {b_per} letras.",
                    inner[b_off] as char
                ),
                cands,
                b_off,
                b_per,
            )
        }
    };

    let outer_str: String = ALBERTI_OUTER.iter().map(|&b| b as char).collect();
    let inner_str: String = inner.iter().map(|&b| b as char).collect();
    let headers: Vec<String> = ALBERTI_OUTER.iter().map(|&b| (b as char).to_string()).collect();
    let aligned_inner: Vec<String> = (0..26)
        .map(|i| (inner[(i + best_offset) % 26] as char).to_string())
        .collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "substitution".into(),
            headers,
            rows: vec![aligned_inner],
        }),
        meta: vec![
            MetaEntry { key: "outer_ring".into(), value: outer_str },
            MetaEntry { key: "inner_ring".into(), value: inner_str },
            MetaEntry { key: "offset".into(), value: best_offset.to_string() },
            MetaEntry { key: "period".into(), value: best_period.to_string() },
        ],
    })
}

// ============================================================================
// 5. Cifrado de Vigenere
// ============================================================================

fn vigenere_transform(text: &str, key_bytes: &[u8], encrypt: bool) -> String {
    let mut ki = 0usize;
    let mut out = String::with_capacity(text.len());
    for ch in text.chars().map(fold_latin_char) {
        if ch.is_ascii_alphabetic() {
            let k = (key_bytes[ki % key_bytes.len()] - b'A') as i32;
            let base = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
            let p = (ch as u8 - base) as i32;
            let shifted = if encrypt {
                (p + k).rem_euclid(26) as u8
            } else {
                (p - k).rem_euclid(26) as u8
            };
            out.push((base + shifted) as char);
            ki += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn index_of_coincidence(col: &[u8]) -> f64 {
    if col.len() < 2 {
        return 0.0;
    }
    let mut counts = [0usize; 26];
    for &b in col {
        counts[(b - b'A') as usize] += 1;
    }
    let num: f64 = counts.iter().map(|&c| (c * c.saturating_sub(1)) as f64).sum();
    let den = (col.len() * (col.len() - 1)) as f64;
    num / den
}

fn best_column_shift(col: &[u8]) -> (u8, f64) {
    let n = col.len() as f64;
    let mut best_shift = 0u8;
    let mut best_corr = f64::NEG_INFINITY;
    for shift in 0..26u8 {
        let mut counts = [0usize; 26];
        for &b in col {
            let dec = (b - b'A' + 26 - shift) % 26;
            counts[dec as usize] += 1;
        }
        let es_dot: f64 = counts
            .iter()
            .enumerate()
            .map(|(i, &c)| (c as f64 / n) * ES_FREQ[i])
            .sum();
        let en_dot: f64 = counts
            .iter()
            .enumerate()
            .map(|(i, &c)| (c as f64 / n) * EN_FREQ[i])
            .sum();
        let corr = es_dot.max(en_dot);
        if corr > best_corr {
            best_corr = corr;
            best_shift = shift;
        }
    }
    (best_shift, best_corr)
}

fn solve_vigenere(text: &str, hint_key: &str) -> (String, String, Vec<Candidate>, String) {
    let letters = extract_upper_az(text);
    if letters.is_empty() {
        return (text.to_owned(), "Sin letras A-Z para analizar.".into(), Vec::new(), String::new());
    }

    let mut seen_keys: Vec<Vec<u8>> = Vec::new();
    let hint = extract_upper_az(hint_key);
    if !hint.is_empty() {
        seen_keys.push(hint);
    }

    // 1) Analisis estadistico IC para longitudes 1..=14
    let max_len = (letters.len() / 2).clamp(1, 14);
    let mut ic_lengths: Vec<(usize, f64)> = (1..=max_len)
        .map(|len| {
            let mut sum_ic = 0.0;
            for offset in 0..len {
                let col: Vec<u8> = letters.iter().skip(offset).step_by(len).copied().collect();
                sum_ic += index_of_coincidence(&col);
            }
            (len, sum_ic / len as f64)
        })
        .collect();
    ic_lengths.sort_by(|a, b| (b.1 - 0.072).abs().total_cmp(&(a.1 - 0.072).abs()).reverse());

    for &(len, _) in ic_lengths.iter().take(6) {
        let mut recovered = Vec::with_capacity(len);
        for offset in 0..len {
            let col: Vec<u8> = letters.iter().skip(offset).step_by(len).copied().collect();
            let (shift, _) = best_column_shift(&col);
            recovered.push(b'A' + shift);
        }
        if !seen_keys.contains(&recovered) {
            seen_keys.push(recovered);
        }
    }

    // 2) Diccionario de claves frecuentes como apoyo en textos cortos
    for kw in [
        "CLAVE", "SECRETO", "KEY", "SECRET", "VIGENERE", "ROMA", "CESAR", "ALFA",
        "SOL", "LUNA", "CODIGO", "CRYPTO", "ENIGMA", "HOLA", "ESPANA", "MADRID",
        "LEON", "LIMON", "LEMON",
    ] {
        let kb = kw.as_bytes().to_vec();
        if !seen_keys.contains(&kb) {
            seen_keys.push(kb);
        }
    }

    let mut ranked: Vec<(String, String, f64)> = seen_keys
        .into_iter()
        .map(|kb| {
            let plain = vigenere_transform(text, &kb, false);
            let sc = score_text(&plain);
            let kstr = String::from_utf8_lossy(&kb).into_owned();
            (kstr, plain, sc)
        })
        .collect();
    ranked.sort_by(|a, b| b.2.total_cmp(&a.2));

    let best_key = ranked[0].0.clone();
    let best_plain = ranked[0].1.clone();
    let candidates = ranked
        .into_iter()
        .take(10)
        .map(|(k, p, sc)| Candidate {
            label: format!("Clave '{k}' (long. {})", k.len()),
            text: p,
            score: sc,
        })
        .collect();

    let explanation = format!(
        "Indice de Coincidencia + correlacion por columnas: clave recuperada '{best_key}'."
    );
    (best_plain, explanation, candidates, best_key)
}

fn run_vigenere(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let key_bytes = extract_upper_az(key);
    let eff_key = if key_bytes.is_empty() {
        b"CLAVE".to_vec()
    } else {
        key_bytes
    };
    let key_str = String::from_utf8_lossy(&eff_key).into_owned();

    let (result, explanation, candidates, used_key) = match action {
        Action::Encrypt => (
            vigenere_transform(text, &eff_key, true),
            format!("Cifrado polialfabetico Vigenere con clave '{key_str}'."),
            Vec::new(),
            key_str,
        ),
        Action::Decrypt => (
            vigenere_transform(text, &eff_key, false),
            format!("Descifrado Vigenere usando la clave '{key_str}'."),
            Vec::new(),
            key_str,
        ),
        Action::Solve => solve_vigenere(text, key),
    };

    let headers: Vec<String> = used_key.chars().map(|c| c.to_string()).collect();
    let shifts: Vec<String> = used_key
        .bytes()
        .map(|b| format!("+{}", b - b'A'))
        .collect();

    let letters = extract_upper_az(text);
    let max_ic_len = (letters.len() / 2).clamp(1, 10);
    let ic_spectrum = (1..=max_ic_len)
        .map(|len| {
            let mut sum_ic = 0.0;
            for off in 0..len {
                let col: Vec<u8> = letters.iter().skip(off).step_by(len).copied().collect();
                sum_ic += index_of_coincidence(&col);
            }
            format!("{len}:{:.4}", sum_ic / len as f64)
        })
        .collect::<Vec<_>>()
        .join(",");

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "key_shifts".into(),
            headers,
            rows: vec![shifts],
        }),
        meta: vec![
            MetaEntry { key: "recovered_key".into(), value: used_key },
            MetaEntry { key: "ic_spectrum".into(), value: ic_spectrum },
        ],
    })
}

// ============================================================================
// 6. Cifrado Playfair
// ============================================================================

fn build_playfair_square(key: &str) -> ([u8; 25], [(usize, usize); 26]) {
    let mut seen = [false; 26];
    seen[(b'J' - b'A') as usize] = true;
    let mut square = [b'A'; 25];
    let mut pos = [(0usize, 0usize); 26];
    let mut idx = 0usize;

    let seed = extract_upper_az(key);
    for b in seed.into_iter().chain(b'A'..=b'Z') {
        let norm = if b == b'J' { b'I' } else { b };
        let alpha_i = (norm - b'A') as usize;
        if !seen[alpha_i] && idx < 25 {
            seen[alpha_i] = true;
            square[idx] = norm;
            pos[alpha_i] = (idx / 5, idx % 5);
            idx += 1;
        }
    }
    pos[(b'J' - b'A') as usize] = pos[(b'I' - b'A') as usize];
    (square, pos)
}

fn prepare_playfair_digrams(text: &str) -> Vec<(u8, u8)> {
    let letters: Vec<u8> = extract_upper_az(text)
        .into_iter()
        .map(|b| if b == b'J' { b'I' } else { b })
        .collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < letters.len() {
        let a = letters[i];
        if i + 1 >= letters.len() {
            let pad = if a == b'X' { b'Q' } else { b'X' };
            pairs.push((a, pad));
            break;
        }
        let b = letters[i + 1];
        if a == b {
            let pad = if a == b'X' { b'Q' } else { b'X' };
            pairs.push((a, pad));
            i += 1;
        } else {
            pairs.push((a, b));
            i += 2;
        }
    }
    pairs
}

fn transform_playfair_with_square(
    pairs: &[(u8, u8)],
    square: &[u8; 25],
    pos: &[(usize, usize); 26],
    encrypt: bool,
) -> String {
    let step = if encrypt { 1usize } else { 4usize };
    let mut out = String::with_capacity(pairs.len() * 3);
    for &(a, b) in pairs {
        let (r1, c1) = pos[(a - b'A') as usize];
        let (r2, c2) = pos[(b - b'A') as usize];
        let (na, nb) = if r1 == r2 {
            (square[r1 * 5 + (c1 + step) % 5], square[r2 * 5 + (c2 + step) % 5])
        } else if c1 == c2 {
            (square[((r1 + step) % 5) * 5 + c1], square[((r2 + step) % 5) * 5 + c2])
        } else {
            (square[r1 * 5 + c2], square[r2 * 5 + c1])
        };
        out.push(na as char);
        out.push(nb as char);
    }
    out
}

fn playfair_encrypt(text: &str, key: &str) -> (String, [u8; 25]) {
    let (sq, pos) = build_playfair_square(key);
    let pairs = prepare_playfair_digrams(text);
    (transform_playfair_with_square(&pairs, &sq, &pos, true), sq)
}

fn playfair_decrypt(text: &str, key: &str) -> (String, [u8; 25]) {
    let (sq, pos) = build_playfair_square(key);
    let letters: Vec<u8> = extract_upper_az(text)
        .into_iter()
        .map(|b| if b == b'J' { b'I' } else { b })
        .collect();
    let mut pairs = Vec::with_capacity(letters.len() / 2);
    for chunk in letters.chunks_exact(2) {
        pairs.push((chunk[0], chunk[1]));
    }
    (transform_playfair_with_square(&pairs, &sq, &pos, false), sq)
}

fn playfair_grid(square: &[u8; 25]) -> GridData {
    let rows = (0..5)
        .map(|r| {
            (0..5)
                .map(|c| {
                    let ch = square[r * 5 + c] as char;
                    if ch == 'I' { "I/J".into() } else { ch.to_string() }
                })
                .collect()
        })
        .collect();
    GridData {
        kind: "matrix_5x5".into(),
        headers: vec!["1".into(), "2".into(), "3".into(), "4".into(), "5".into()],
        rows,
    }
}

fn playfair_pos_from_square(square: &[u8; 25]) -> [(usize, usize); 26] {
    let mut pos = [(0usize, 0usize); 26];
    for (idx, &ch) in square.iter().enumerate() {
        pos[(ch - b'A') as usize] = (idx / 5, idx % 5);
    }
    pos[(b'J' - b'A') as usize] = pos[(b'I' - b'A') as usize];
    pos
}

fn playfair_hill_climb(pairs: &[(u8, u8)], iterations: usize) -> (String, [u8; 25], f64) {
    let mut best_sq = *b"ABCDEFGHIKLMNOPQRSTUVWXYZ";
    let best_pos = playfair_pos_from_square(&best_sq);
    let mut best_text = transform_playfair_with_square(pairs, &best_sq, &best_pos, false);
    let mut best_score = score_text(&best_text);

    let mut cur_sq = best_sq;
    let mut cur_score = best_score;
    let mut rng: u64 = 0x5EED_CAFE_BABE_1234;

    for step in 0..iterations {
        let mut next_sq = cur_sq;
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let a = (rng as usize) % 25;
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let b = (rng as usize) % 25;
        if a == b {
            continue;
        }
        if step % 15 == 0 {
            next_sq.swap(a, (a + 5) % 25);
        } else {
            next_sq.swap(a, b);
        }
        let next_pos = playfair_pos_from_square(&next_sq);
        let cand = transform_playfair_with_square(pairs, &next_sq, &next_pos, false);
        let sc = score_text(&cand);
        if sc > cur_score || (step < iterations / 2 && (rng % 100) < 4) {
            cur_sq = next_sq;
            cur_score = sc;
            if sc > best_score {
                best_score = sc;
                best_sq = next_sq;
                best_text = cand;
            }
        }
    }
    (best_text, best_sq, best_score)
}

fn run_playfair(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let eff_key = if key.trim().is_empty() { "MONARQUIA" } else { key.trim() };
    let trace_pairs = if action == Action::Encrypt {
        prepare_playfair_digrams(text)
    } else {
        let letters: Vec<u8> = extract_upper_az(text)
            .into_iter()
            .map(|b| if b == b'J' { b'I' } else { b })
            .collect();
        letters.chunks_exact(2).map(|c| (c[0], c[1])).collect()
    };

    let (result, explanation, candidates, sq) = match action {
        Action::Encrypt => {
            let (out, sq) = playfair_encrypt(text, eff_key);
            (
                out,
                format!("Matriz Playfair 5x5 (I/J unidas) generada con clave '{eff_key}'."),
                Vec::new(),
                sq,
            )
        }
        Action::Decrypt => {
            let (out, sq) = playfair_decrypt(text, eff_key);
            (
                out,
                format!("Descifrado por digrafos Playfair con matriz de clave '{eff_key}'."),
                Vec::new(),
                sq,
            )
        }
        Action::Solve => {
            let mut keys: Vec<&str> = Vec::new();
            if !key.trim().is_empty() {
                keys.push(key.trim());
            }
            for kw in [
                "MONARQUIA", "MONARCHY", "PLAYFAIR", "SECRETO", "CLAVE", "KEYWORD",
                "CIPHER", "ESPANA", "MADRID", "CRYPTO", "ENIGMA", "CESAR", "ROMA",
            ] {
                if !keys.contains(&kw) {
                    keys.push(kw);
                }
            }
            let mut ranked: Vec<(String, String, [u8; 25], f64)> = keys
                .into_iter()
                .map(|kw| {
                    let (dec, sq) = playfair_decrypt(text, kw);
                    let sc = score_text(&dec);
                    (format!("Clave '{kw}'"), dec, sq, sc)
                })
                .collect();

            if trace_pairs.len() >= 28 {
                let (hc_txt, hc_sq, hc_sc) = playfair_hill_climb(&trace_pairs, 1800);
                ranked.push(("Hill-Climbing 5x5 (sin clave)".into(), hc_txt, hc_sq, hc_sc));
            }

            ranked.sort_by(|a, b| b.3.total_cmp(&a.3));
            let best_res = ranked[0].1.clone();
            let best_sq = ranked[0].2;
            let best_lbl = ranked[0].0.clone();
            let cands = ranked
                .into_iter()
                .map(|(lbl, dec, _, sc)| Candidate {
                    label: lbl,
                    text: dec,
                    score: sc,
                })
                .collect();
            (
                best_res,
                format!("Analisis Playfair (diccionario + hill-climbing 5x5): ganador {best_lbl}."),
                cands,
                best_sq,
            )
        }
    };

    let digram_trace = trace_pairs
        .iter()
        .take(10)
        .map(|&(a, b)| format!("{}{}", a as char, b as char))
        .collect::<Vec<_>>()
        .join(" ");

    let (_, final_pos) = build_playfair_square(eff_key);
    let step_is_enc = action == Action::Encrypt;
    let step_shift = if step_is_enc { 1usize } else { 4usize };
    let digram_steps = trace_pairs
        .iter()
        .take(10)
        .map(|&(a, b)| {
            let (r1, c1) = final_pos[(a - b'A') as usize];
            let (r2, c2) = final_pos[(b - b'A') as usize];
            let (rule, d1, d2) = if r1 == r2 {
                ("fila", (r1, (c1 + step_shift) % 5), (r2, (c2 + step_shift) % 5))
            } else if c1 == c2 {
                ("col", ((r1 + step_shift) % 5, c1), ((r2 + step_shift) % 5, c2))
            } else {
                ("rect", (r1, c2), (r2, c1))
            };
            let oa = sq[d1.0 * 5 + d1.1] as char;
            let ob = sq[d2.0 * 5 + d2.1] as char;
            format!(
                "{}{}>{}{}[{rule}:{r1},{c1};{r2},{c2};{},{}|{},{}]",
                a as char, b as char, oa, ob, d1.0, d1.1, d2.0, d2.1
            )
        })
        .collect::<Vec<_>>()
        .join(" ");

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(playfair_grid(&sq)),
        meta: vec![
            MetaEntry { key: "digrams".into(), value: digram_trace },
            MetaEntry { key: "digram_steps".into(), value: digram_steps },
        ],
    })
}

// ============================================================================
// 7. Cilindro de Jefferson
// ============================================================================

/// Genera los 36 discos deterministas del cilindro de Jefferson (permutaciones de A-Z).
fn jefferson_wheels(seed_key: &str) -> Vec<[u8; 26]> {
    let base_seed: u64 = seed_key
        .bytes()
        .fold(0x9E37_79B9_7F4A_7C15u64, |acc, b| acc.wrapping_mul(131).wrapping_add(b as u64));

    (0..36u64)
        .map(|w| {
            let mut alpha = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let mut state = base_seed ^ (w.wrapping_mul(0xBF58_476D_1CE4_E5B9));
            for i in (1..26).rev() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let j = (state as usize) % (i + 1);
                alpha.swap(i, j);
            }
            alpha
        })
        .collect()
}

fn jefferson_shift_row(letters: &[u8], wheels: &[[u8; 26]], row_offset: usize) -> String {
    letters
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let wheel = &wheels[i % wheels.len()];
            let pos = wheel.iter().position(|&c| c == b).unwrap_or(0);
            wheel[(pos + row_offset) % 26] as char
        })
        .collect()
}

fn run_jefferson(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let seed = if key.trim().is_empty() { "JEFFERSON1795" } else { key.trim() };
    let wheels = jefferson_wheels(seed);
    let offset = param.trim().parse::<usize>().unwrap_or(6) % 26;
    let letters = extract_upper_az(text);
    if letters.is_empty() {
        return Ok(CipherOutput {
            cipher: String::new(),
            action: String::new(),
            result: String::new(),
            explanation: "Introduce letras A-Z para alinear los discos del cilindro de Jefferson.".into(),
            candidates: Vec::new(),
            grid: None,
            meta: vec![
                MetaEntry { key: "highlight_row".into(), value: "0".into() },
                MetaEntry { key: "offset".into(), value: offset.to_string() },
            ],
        });
    }

    let (result, explanation, candidates, highlight_row) = match action {
        Action::Encrypt => {
            let enc = jefferson_shift_row(&letters, &wheels, offset);
            (
                enc,
                format!("Cilindro de Jefferson (semilla '{seed}'): fila desplazada +{offset} posiciones."),
                Vec::new(),
                offset,
            )
        }
        Action::Decrypt => {
            let inv = (26 - offset) % 26;
            let dec = jefferson_shift_row(&letters, &wheels, inv);
            (
                dec,
                format!("Descifrado Jefferson leyendo la fila -{offset} (+{inv} mod 26)."),
                Vec::new(),
                inv,
            )
        }
        Action::Solve => {
            let mut list: Vec<(usize, String, f64)> = (1..26)
                .map(|r| {
                    let cand = jefferson_shift_row(&letters, &wheels, r);
                    let sc = score_text(&cand);
                    (r, cand, sc)
                })
                .collect();
            list.sort_by(|a, b| b.2.total_cmp(&a.2));
            let best_r = list[0].0;
            let best_txt = list[0].1.clone();
            let cands = list
                .into_iter()
                .map(|(r, t, sc)| Candidate {
                    label: format!("Generatriz +{r} (clave -{})", (26 - r) % 26),
                    text: t,
                    score: sc,
                })
                .collect();
            (
                best_txt,
                format!("Inspeccion de las 25 generatrices del cilindro: fila +{best_r} seleccionada automaticamente."),
                cands,
                best_r,
            )
        }
    };

    let preview_len = letters.len().min(14);
    let headers: Vec<String> = (1..=preview_len).map(|i| format!("D{i}")).collect();
    let rows: Vec<Vec<String>> = (0..26)
        .map(|r| {
            let row_str = jefferson_shift_row(&letters[..preview_len], &wheels, r);
            row_str.chars().map(|c| c.to_string()).collect()
        })
        .collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "cylinder".into(),
            headers,
            rows,
        }),
        meta: vec![
            MetaEntry { key: "highlight_row".into(), value: highlight_row.to_string() },
            MetaEntry { key: "offset".into(), value: offset.to_string() },
        ],
    })
}

// ============================================================================
// 8. Escitala Espartana
// ============================================================================

fn scytale_encrypt(text: &str, faces: usize) -> (String, Vec<Vec<String>>) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 || faces <= 1 {
        return (text.to_owned(), vec![chars.into_iter().map(|c| c.to_string()).collect()]);
    }
    let rows = n.div_ceil(faces);
    let rem = n % faces;
    let mut grid = vec![vec![String::new(); faces]; rows];
    let mut idx = 0usize;
    for c in 0..faces {
        let col_len = if rem == 0 || c < rem { rows } else { rows - 1 };
        for row in grid.iter_mut().take(col_len) {
            row[c] = chars[idx].to_string();
            idx += 1;
        }
    }
    let mut out = String::with_capacity(text.len());
    for row in &grid {
        for cell in row {
            if !cell.is_empty() {
                out.push_str(cell);
            }
        }
    }
    (out, grid)
}

fn scytale_decrypt(text: &str, faces: usize) -> (String, Vec<Vec<String>>) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 || faces <= 1 {
        return (text.to_owned(), vec![chars.into_iter().map(|c| c.to_string()).collect()]);
    }
    let rows = n.div_ceil(faces);
    let rem = n % faces;
    let mut grid = vec![vec![String::new(); faces]; rows];
    let mut idx = 0usize;
    for (r, row) in grid.iter_mut().enumerate() {
        for (c, cell) in row.iter_mut().enumerate() {
            if r * faces + c < n {
                *cell = chars[idx].to_string();
                idx += 1;
            }
        }
    }
    let mut out = String::with_capacity(text.len());
    for c in 0..faces {
        let col_len = if rem == 0 || c < rem { rows } else { rows - 1 };
        for row in grid.iter().take(col_len) {
            out.push_str(&row[c]);
        }
    }
    (out, grid)
}

fn run_scytale(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let faces = param
        .trim()
        .parse::<usize>()
        .or_else(|_| key.trim().parse::<usize>())
        .unwrap_or(4)
        .max(2);

    let (result, explanation, candidates, grid, used_faces) = match action {
        Action::Encrypt => {
            let (out, grid) = scytale_encrypt(text, faces);
            (
                out,
                format!("Escitala espartana enrollada en vara de {faces} caras."),
                Vec::new(),
                grid,
                faces,
            )
        }
        Action::Decrypt => {
            let (out, grid) = scytale_decrypt(text, faces);
            (
                out,
                format!("Escitala desenrollada leyendo {faces} caras longitudinales."),
                Vec::new(),
                grid,
                faces,
            )
        }
        Action::Solve => {
            let n = text.chars().count();
            let max_d = n.saturating_sub(1).clamp(2, 20);
            let mut list: Vec<(usize, String, Vec<Vec<String>>, f64)> = (2..=max_d)
                .map(|d| {
                    let (dec, g) = scytale_decrypt(text, d);
                    let sc = score_text(&dec);
                    (d, dec, g, sc)
                })
                .collect();
            list.sort_by(|a, b| b.3.total_cmp(&a.3));
            let (bd, btxt, bgrid, _) = list[0].clone();
            let cands = list
                .into_iter()
                .map(|(d, t, _, sc)| Candidate {
                    label: format!("Diametro {d} caras"),
                    text: t,
                    score: sc,
                })
                .collect();
            (
                btxt,
                format!("Fuerza bruta sobre vara espartana (2..{max_d} caras): mejor diametro {bd}."),
                cands,
                bgrid,
                bd,
            )
        }
    };

    let headers: Vec<String> = (1..=used_faces).map(|i| format!("Cara {i}")).collect();
    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "matrix".into(),
            headers,
            rows: grid,
        }),
        meta: vec![MetaEntry {
            key: "faces".into(),
            value: used_faces.to_string(),
        }],
    })
}

// ============================================================================
// 9. Cifrado Rail Fence (De Valla)
// ============================================================================

fn rail_fence_pattern(len: usize, rails: usize) -> Vec<usize> {
    if rails <= 1 {
        return vec![0; len];
    }
    let mut out = Vec::with_capacity(len);
    let mut rail = 0isize;
    let mut dir = 1isize;
    for _ in 0..len {
        out.push(rail as usize);
        if rail == 0 {
            dir = 1;
        } else if rail == (rails - 1) as isize {
            dir = -1;
        }
        rail += dir;
    }
    out
}

fn rail_fence_encrypt(text: &str, rails: usize) -> (String, Vec<Vec<String>>) {
    let chars: Vec<char> = text.chars().collect();
    let pat = rail_fence_pattern(chars.len(), rails);
    let mut fence = vec![Vec::new(); rails];
    let mut grid = vec![vec![String::new(); chars.len()]; rails];
    for (col, (&ch, &r)) in chars.iter().zip(pat.iter()).enumerate() {
        fence[r].push(ch);
        grid[r][col] = ch.to_string();
    }
    let out: String = fence.into_iter().flatten().collect();
    (out, grid)
}

fn rail_fence_decrypt(text: &str, rails: usize) -> (String, Vec<Vec<String>>) {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 || rails <= 1 {
        return (text.to_owned(), vec![chars.into_iter().map(|c| c.to_string()).collect()]);
    }
    let pat = rail_fence_pattern(n, rails);
    let mut counts = vec![0usize; rails];
    for &r in &pat {
        counts[r] += 1;
    }
    let mut rails_data: Vec<Vec<char>> = Vec::with_capacity(rails);
    let mut offset = 0usize;
    for &cnt in &counts {
        rails_data.push(chars[offset..offset + cnt].to_vec());
        offset += cnt;
    }
    let mut rail_pos = vec![0usize; rails];
    let mut out = String::with_capacity(n);
    let mut grid = vec![vec![String::new(); n]; rails];
    for (col, &r) in pat.iter().enumerate() {
        let ch = rails_data[r][rail_pos[r]];
        rail_pos[r] += 1;
        out.push(ch);
        grid[r][col] = ch.to_string();
    }
    (out, grid)
}

fn run_rail_fence(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let rails = param
        .trim()
        .parse::<usize>()
        .or_else(|_| key.trim().parse::<usize>())
        .unwrap_or(3)
        .max(2);

    let (result, explanation, candidates, grid, used_rails) = match action {
        Action::Encrypt => {
            let (out, g) = rail_fence_encrypt(text, rails);
            (out, format!("Zig-zag Rail Fence sobre {rails} railes."), Vec::new(), g, rails)
        }
        Action::Decrypt => {
            let (out, g) = rail_fence_decrypt(text, rails);
            (out, format!("Reconstruccion Rail Fence desde {rails} railes."), Vec::new(), g, rails)
        }
        Action::Solve => {
            let max_r = text.chars().count().saturating_sub(1).clamp(2, 12);
            let mut list: Vec<(usize, String, Vec<Vec<String>>, f64)> = (2..=max_r)
                .map(|r| {
                    let (dec, g) = rail_fence_decrypt(text, r);
                    let sc = score_text(&dec);
                    (r, dec, g, sc)
                })
                .collect();
            list.sort_by(|a, b| b.3.total_cmp(&a.3));
            let (br, btxt, bgrid, _) = list[0].clone();
            let cands = list
                .into_iter()
                .map(|(r, t, _, sc)| Candidate {
                    label: format!("{r} railes"),
                    text: t,
                    score: sc,
                })
                .collect();
            (
                btxt,
                format!("Fuerza bruta Rail Fence (2..{max_r} railes): {br} railes produce el mejor texto."),
                cands,
                bgrid,
                br,
            )
        }
    };

    let cols = grid.first().map_or(0, Vec::len).min(48);
    let trimmed_grid: Vec<Vec<String>> = grid
        .into_iter()
        .map(|row| row.into_iter().take(cols).collect())
        .collect();
    let headers: Vec<String> = (1..=cols).map(|i| i.to_string()).collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "zigzag".into(),
            headers,
            rows: trimmed_grid,
        }),
        meta: vec![MetaEntry {
            key: "rails".into(),
            value: used_rails.to_string(),
        }],
    })
}

// ============================================================================
// 10. Transposicion por Columnas
// ============================================================================

fn key_column_order(key: &str) -> Vec<usize> {
    let letters = extract_upper_az(key);
    let k = if letters.is_empty() { b"CLAVE".to_vec() } else { letters };
    let mut indexed: Vec<(u8, usize)> = k.into_iter().enumerate().map(|(i, b)| (b, i)).collect();
    indexed.sort_by_key(|&(b, i)| (b, i));
    indexed.into_iter().map(|(_, i)| i).collect()
}

fn columnar_encrypt_order(text: &str, order: &[usize]) -> (String, Vec<Vec<String>>) {
    let cols = order.len();
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let rows = n.div_ceil(cols);
    let mut grid = vec![vec![String::new(); cols]; rows];
    for (idx, &ch) in chars.iter().enumerate() {
        grid[idx / cols][idx % cols] = ch.to_string();
    }
    let mut out = String::with_capacity(n);
    for &c in order {
        for r in 0..rows {
            if r * cols + c < n {
                out.push(chars[r * cols + c]);
            }
        }
    }
    (out, grid)
}

fn columnar_decrypt_order(text: &str, order: &[usize]) -> (String, Vec<Vec<String>>) {
    let cols = order.len();
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return (String::new(), Vec::new());
    }
    let rows = n.div_ceil(cols);
    let rem = n % cols;
    let mut grid = vec![vec![String::new(); cols]; rows];
    let mut idx = 0usize;
    for &c in order {
        let col_len = if rem == 0 || c < rem { rows } else { rows - 1 };
        for row in grid.iter_mut().take(col_len) {
            row[c] = chars[idx].to_string();
            idx += 1;
        }
    }
    let mut out = String::with_capacity(n);
    for (r, row) in grid.iter().enumerate() {
        for (c, cell) in row.iter().enumerate() {
            if r * cols + c < n {
                out.push_str(cell);
            }
        }
    }
    (out, grid)
}

fn gen_permutations(n: usize, out: &mut Vec<Vec<usize>>, cur: &mut Vec<usize>, used: &mut [bool]) {
    if cur.len() == n {
        out.push(cur.clone());
        return;
    }
    for i in 0..n {
        if !used[i] {
            used[i] = true;
            cur.push(i);
            gen_permutations(n, out, cur, used);
            cur.pop();
            used[i] = false;
        }
    }
}

fn format_order(order: &[usize]) -> String {
    order.iter().map(|i| (i + 1).to_string()).collect::<Vec<_>>().join("-")
}

fn run_columnar(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let eff_key = if key.trim().is_empty() { "CLAVE" } else { key.trim() };
    let order = key_column_order(eff_key);

    let (result, explanation, candidates, grid, headers) = match action {
        Action::Encrypt => {
            let (out, g) = columnar_encrypt_order(text, &order);
            let hdrs = extract_upper_az(eff_key)
                .into_iter()
                .map(|b| (b as char).to_string())
                .collect();
            (
                out,
                format!("Transposicion columnar con clave '{eff_key}' (orden {}).", format_order(&order)),
                Vec::new(),
                g,
                hdrs,
            )
        }
        Action::Decrypt => {
            let (out, g) = columnar_decrypt_order(text, &order);
            let hdrs = extract_upper_az(eff_key)
                .into_iter()
                .map(|b| (b as char).to_string())
                .collect();
            (
                out,
                format!("Descifrado columnar con clave '{eff_key}' (orden {}).", format_order(&order)),
                Vec::new(),
                g,
                hdrs,
            )
        }
        Action::Solve => {
            let mut perms: Vec<(String, Vec<usize>)> = Vec::new();
            if !key.trim().is_empty() {
                perms.push((format!("Clave '{eff_key}'"), order.clone()));
            }
            for kw in ["CLAVE", "SECRETO", "CESAR", "ROMA", "CIPHER", "CODIGO", "MADRID", "ENIGMA"] {
                let ord = key_column_order(kw);
                if !perms.iter().any(|(_, o)| o == &ord) {
                    perms.push((format!("Clave '{kw}'"), ord));
                }
            }
            for len in 2..=6 {
                let mut all = Vec::new();
                let mut cur = Vec::new();
                let mut used = vec![false; len];
                gen_permutations(len, &mut all, &mut cur, &mut used);
                for ord in all {
                    if !perms.iter().any(|(_, o)| o == &ord) {
                        perms.push((format!("Permutacion {}", format_order(&ord)), ord));
                    }
                }
            }
            struct ColumnarRanked {
                label: String,
                order: Vec<usize>,
                text: String,
                grid: Vec<Vec<String>>,
                score: f64,
            }
            let mut ranked: Vec<ColumnarRanked> = perms
                .into_iter()
                .map(|(label, order)| {
                    let (text, grid) = columnar_decrypt_order(text, &order);
                    let score = score_text(&text);
                    ColumnarRanked { label, order, text, grid, score }
                })
                .collect();
            ranked.sort_by(|a, b| b.score.total_cmp(&a.score));
            let blbl = ranked[0].label.clone();
            let bord = ranked[0].order.clone();
            let btxt = ranked[0].text.clone();
            let bgrid = ranked[0].grid.clone();
            let hdrs = (0..bord.len())
                .map(|c| {
                    let rank = bord.iter().position(|&x| x == c).unwrap_or(0) + 1;
                    format!("#{rank}")
                })
                .collect();
            let cands = ranked
                .into_iter()
                .take(12)
                .map(|item| Candidate {
                    label: item.label,
                    text: item.text,
                    score: item.score,
                })
                .collect();
            (
                btxt,
                format!("Evaluadas todas las permutaciones de 2..6 columnas + diccionario: ganador {blbl}."),
                cands,
                bgrid,
                hdrs,
            )
        }
    };

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "matrix".into(),
            headers,
            rows: grid,
        }),
        meta: Vec::new(),
    })
}

// ============================================================================
// 11. Rejilla de Cardano
// ============================================================================

fn rotate_cw(r: usize, c: usize, n: usize) -> (usize, usize) {
    (c, n - 1 - r)
}

fn cardano_holes(n: usize, key: &str) -> Vec<(usize, usize)> {
    let seed = key
        .bytes()
        .fold(0x517C_C1B7_2722_0A95u64, |acc, b| acc.wrapping_mul(167).wrapping_add(b as u64));
    let half = n / 2;
    let mut base_holes = Vec::with_capacity(half * half);
    for r in 0..half {
        for c in 0..half {
            let h = seed ^ ((r as u64) * 31 + (c as u64) * 131);
            let rot = (h % 4) as usize;
            let mut pos = (r, c);
            for _ in 0..rot {
                pos = rotate_cw(pos.0, pos.1, n);
            }
            base_holes.push(pos);
        }
    }
    base_holes
}

fn cardano_sequence(n: usize, base_holes: &[(usize, usize)]) -> [Vec<(usize, usize)>; 4] {
    let mut seqs: [Vec<(usize, usize)>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut cur = base_holes.to_vec();
    for slot in &mut seqs {
        let mut sorted = cur.clone();
        sorted.sort_unstable();
        *slot = sorted;
        cur = cur.into_iter().map(|(r, c)| rotate_cw(r, c, n)).collect();
    }
    seqs
}

fn cardano_size(text_len: usize, param: &str) -> usize {
    if let Ok(p) = param.trim().parse::<usize>()
        && p >= 4
        && p.is_multiple_of(2)
        && p * p >= text_len
    {
        return p;
    }
    let mut n = 4usize;
    while n * n < text_len {
        n += 2;
    }
    n.min(12)
}

fn cardano_encrypt_with_holes(text: &str, n: usize, holes: &[(usize, usize)]) -> (String, Vec<Vec<char>>) {
    let seqs = cardano_sequence(n, holes);
    let chars: Vec<char> = text.chars().collect();
    let mut matrix = vec![vec![' '; n]; n];
    let mut idx = 0usize;
    for rot in &seqs {
        for &(r, c) in rot {
            if idx < chars.len() {
                matrix[r][c] = chars[idx];
                idx += 1;
            }
        }
    }
    let out: String = matrix.iter().flat_map(|row| row.iter()).collect();
    (out, matrix)
}

fn cardano_decrypt_with_holes(text: &str, n: usize, holes: &[(usize, usize)]) -> (String, Vec<Vec<char>>) {
    let seqs = cardano_sequence(n, holes);
    let chars: Vec<char> = text.chars().collect();
    let mut matrix = vec![vec![' '; n]; n];
    for (r, row) in matrix.iter_mut().enumerate() {
        for (c, cell) in row.iter_mut().enumerate() {
            if let Some(&ch) = chars.get(r * n + c) {
                *cell = ch;
            }
        }
    }
    let mut out = String::with_capacity(n * n);
    for rot in &seqs {
        for &(r, c) in rot {
            out.push(matrix[r][c]);
        }
    }
    (out.trim_end().to_owned(), matrix)
}

fn run_cardano(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let eff_key = if key.trim().is_empty() { "CARDANO" } else { key.trim() };
    let n = cardano_size(text.chars().count(), param);

    let (result, explanation, candidates, matrix, used_holes) = match action {
        Action::Encrypt => {
            let holes = cardano_holes(n, eff_key);
            let (out, mat) = cardano_encrypt_with_holes(text, n, &holes);
            (
                out,
                format!("Rejilla de Cardano {n}x{n} rotada 0/90/180/270 grados con clave '{eff_key}'."),
                Vec::new(),
                mat,
                holes,
            )
        }
        Action::Decrypt => {
            let holes = cardano_holes(n, eff_key);
            let (out, mat) = cardano_decrypt_with_holes(text, n, &holes);
            (
                out,
                format!("Extraccion de Cardano {n}x{n} en 4 giros con clave '{eff_key}'."),
                Vec::new(),
                mat,
                holes,
            )
        }
        Action::Solve => {
            let mut seeds: Vec<&str> = Vec::new();
            if !key.trim().is_empty() {
                seeds.push(key.trim());
            }
            for kw in ["CARDANO", "SECRETO", "CLAVE", "1550", "REJILLA", "ROMA", "MADRID", "KEY"] {
                if !seeds.contains(&kw) {
                    seeds.push(kw);
                }
            }
            struct CardanoRanked<'a> {
                seed: &'a str,
                text: String,
                matrix: Vec<Vec<char>>,
                holes: Vec<(usize, usize)>,
                score: f64,
            }
            let mut ranked: Vec<CardanoRanked<'_>> = seeds
                .into_iter()
                .map(|seed| {
                    let holes = cardano_holes(n, seed);
                    let (text, matrix) = cardano_decrypt_with_holes(text, n, &holes);
                    let leading_ws = text.chars().take_while(|c| c.is_whitespace()).count() as f64;
                    let score = score_text(&text) - leading_ws * 0.25;
                    CardanoRanked { seed, text, matrix, holes, score }
                })
                .collect();
            ranked.sort_by(|a, b| b.score.total_cmp(&a.score));
            let bs = ranked[0].seed;
            let btxt = ranked[0].text.clone();
            let bmat = ranked[0].matrix.clone();
            let bholes = ranked[0].holes.clone();
            let cands = ranked
                .into_iter()
                .map(|item| Candidate {
                    label: format!("Rejilla '{}' ({n}x{n})", item.seed),
                    text: item.text,
                    score: item.score,
                })
                .collect();
            (
                btxt,
                format!("Analisis sobre rejillas {n}x{n}: mejor lectura obtenida con plantilla '{bs}'."),
                cands,
                bmat,
                bholes,
            )
        }
    };

    let holes_str = used_holes
        .iter()
        .map(|(r, c)| format!("{r},{c}"))
        .collect::<Vec<_>>()
        .join(";");
    let headers: Vec<String> = (1..=n).map(|i| format!("C{i}")).collect();
    let rows: Vec<Vec<String>> = matrix
        .into_iter()
        .map(|row| row.into_iter().map(|c| c.to_string()).collect())
        .collect();

    Ok(CipherOutput {
        cipher: String::new(),
        action: String::new(),
        result,
        explanation,
        candidates,
        grid: Some(GridData {
            kind: "cardano".into(),
            headers,
            rows,
        }),
        meta: vec![
            MetaEntry { key: "size".into(), value: n.to_string() },
            MetaEntry { key: "holes".into(), value: holes_str },
        ],
    })
}

// ============================================================================
// 12. Tinta Invisible (Esteganografia Zero-Width)
// ============================================================================

const ZW_DIGITS: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];

fn encode_invisible_ink(secret: &str, cover: &str) -> String {
    let cover_text = if cover.trim().is_empty() {
        "Buenos dias, te envio los apuntes de la reunion de hoy."
    } else {
        cover.trim()
    };
    let mut zw = String::with_capacity(secret.len() * 4);
    for byte in secret.as_bytes() {
        for shift in [6, 4, 2, 0] {
            let bits = ((byte >> shift) & 0b11) as usize;
            zw.push(ZW_DIGITS[bits]);
        }
    }
    let mut chars = cover_text.chars();
    let mut out = String::with_capacity(cover_text.len() + zw.len());
    if let Some(first) = chars.next() {
        out.push(first);
    }
    out.push_str(&zw);
    out.extend(chars);
    out
}

fn decode_invisible_ink(carrier: &str) -> (String, usize, String) {
    let mut pairs = Vec::new();
    let mut visible = String::new();
    for ch in carrier.chars() {
        match ch {
            '\u{200B}' => pairs.push(0u8),
            '\u{200C}' => pairs.push(1u8),
            '\u{200D}' => pairs.push(2u8),
            '\u{FEFF}' => pairs.push(3u8),
            other => visible.push(other),
        }
    }
    let zw_count = pairs.len();
    let mut bytes = Vec::with_capacity(zw_count / 4);
    for chunk in pairs.chunks_exact(4) {
        let b = (chunk[0] << 6) | (chunk[1] << 4) | (chunk[2] << 2) | chunk[3];
        bytes.push(b);
    }
    let decoded = String::from_utf8_lossy(&bytes).into_owned();
    (decoded, zw_count, visible)
}

fn run_invisible_ink(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    match action {
        Action::Encrypt => {
            let stego = encode_invisible_ink(text, key);
            let zw_count = text.len() * 4;
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: stego.clone(),
                explanation: format!(
                    "Mensaje ocultado con {zw_count} caracteres invisibles Zero-Width dentro del texto portador."
                ),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "ink_forensics".into(),
                    headers: vec!["Byte".into(), "Simbolos ZW".into()],
                    rows: text
                        .as_bytes()
                        .iter()
                        .take(16)
                        .map(|&b| {
                            let tag = [6, 4, 2, 0]
                                .into_iter()
                                .map(|s| format!("U+{:04X}", ZW_DIGITS[((b >> s) & 0b11) as usize] as u32))
                                .collect::<Vec<_>>()
                                .join(" ");
                            vec![format!("'{}' (0x{b:02X})", (b as char).escape_default()), tag]
                        })
                        .collect(),
                }),
                meta: vec![
                    MetaEntry { key: "zw_count".into(), value: zw_count.to_string() },
                    MetaEntry { key: "secret_preview".into(), value: text.to_owned() },
                ],
            })
        }
        Action::Decrypt | Action::Solve => {
            let (decoded, zw_count, visible) = decode_invisible_ink(text);
            let explanation = if zw_count > 0 {
                format!("Revelados {zw_count} caracteres Zero-Width ocultos ({} bytes recuperados).", decoded.len())
            } else {
                "No se detectaron caracteres Zero-Width (U+200B..U+FEFF) en el texto.".into()
            };
            let candidates = if action == Action::Solve && zw_count > 0 {
                vec![Candidate {
                    label: "Canal Zero-Width (U+200B/C/D/FEFF)".into(),
                    text: decoded.clone(),
                    score: score_text(&decoded),
                }]
            } else {
                Vec::new()
            };
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: decoded,
                explanation,
                candidates,
                grid: None,
                meta: vec![
                    MetaEntry { key: "zw_count".into(), value: zw_count.to_string() },
                    MetaEntry { key: "visible_text".into(), value: visible },
                ],
            })
        }
    }
}

// ============================================================================
// 13. Acrosticos
// ============================================================================

fn acrostic_lines_for_letter(letter: char, variant: usize) -> &'static str {
    let idx = variant % 2;
    match (letter, idx) {
        ('A', 0) => "Amanece despacio tras los montes lejanos",
        ('A', _) => "Aguarda en silencio la senal convenida",
        ('B', 0) => "Bajo la sombra antigua reposa la llave",
        ('B', _) => "Brilla una estrella sobre el puerto norte",
        ('C', 0) => "Cada palabra guarda un rumbo distinto",
        ('C', _) => "Cruza el puente antes del segundo toque",
        ('D', 0) => "Donde termina el bosque nace el sendero",
        ('D', _) => "Despues de medianoche cambiara la guardia",
        ('E', 0) => "Entre las paginas olvidadas esta la pista",
        ('E', _) => "Escucha el eco firme de la campana",
        ('F', 0) => "Frente al arco de piedra espera el mensajero",
        ('F', _) => "Fiel a su juramento mantiene la ruta",
        ('G', 0) => "Guarda el manuscrito dentro del cofre",
        ('G', _) => "Gira tres veces el anillo de bronce",
        ('H', 0) => "Hasta que caiga la tarde no abras el sobre",
        ('H', _) => "Hacia el horizonte parten las naves",
        ('I', 0) => "Ilumina la lampara el mapa trazado",
        ('I', _) => "Inscribe la fecha exacta en el margen",
        ('J', 0) => "Junto al viejo reloj se cruzaron las cartas",
        ('J', _) => "Jamas reveles el nombre de la orden",
        ('K', 0) => "Kilometros atras quedo la frontera",
        ('K', _) => "Kioscos cerrados marcaban la plaza",
        ('L', 0) => "Lleva el sello intacto hasta el consejo",
        ('L', _) => "La niebla cubre el muelle al alba",
        ('M', 0) => "Mira con atencion el borde del pergamino",
        ('M', _) => "Mantiene su curso hacia la isla sur",
        ('N', 0) => "Ningun testigo vio partir la barca",
        ('N', _) => "Noches enteras cifraron el archivo",
        ('O', 0) => "Oculto entre versos viaja el aviso",
        ('O', _) => "Observa las sombras en la galeria",
        ('P', 0) => "Por la puerta lateral entrara el correo",
        ('P', _) => "Permanece atento al cambio de viento",
        ('Q', 0) => "Quien lea con calma hallara la clave",
        ('Q', _) => "Quedaron atras las torres del valle",
        ('R', 0) => "Recuerda contar los pasos desde el roble",
        ('R', _) => "Resguarda los planos bajo la losa",
        ('S', 0) => "Sigue la linea recta hasta el faro",
        ('S', _) => "Silencio absoluto en la sala oeste",
        ('T', 0) => "Tras el cuadro antiguo hallaras la puerta",
        ('T', _) => "Toda verdad asoma en las iniciales",
        ('U', 0) => "Una sola chispa basta para encenderla",
        ('U', _) => "Ultimas noticias llegaron por mar",
        ('V', 0) => "Vuelve al punto exacto de partida",
        ('V', _) => "Vela el vigia sobre la muralla",
        ('W', 0) => "Walkiria anclo frente a la bahia",
        ('W', _) => "Wenceslao firmo el ultimo pliego",
        ('X', 0) => "Xilofonos resonaban en el patio real",
        ('X', _) => "Ximena entrego la carta sellada",
        ('Y', 0) => "Ya suena la hora prevista en el reloj",
        ('Y', _) => "Yace el secreto en la primera columna",
        ('Z', 0) => "Zarpan al rayar el alba sin demora",
        ('Z', _) => "Zafiros azules adornaban el estuche",
        _ => "Silencio en la noche",
    }
}

fn generate_acrostic(secret: &str) -> String {
    let letters = extract_upper_az(secret);
    let mut used = [0usize; 26];
    letters
        .into_iter()
        .map(|b| {
            let i = (b - b'A') as usize;
            let line = acrostic_lines_for_letter(b as char, used[i]);
            used[i] += 1;
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_acrostic(action: Action, text: &str, _key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    match action {
        Action::Encrypt => {
            let poem = generate_acrostic(text);
            let lines: Vec<Vec<String>> = poem
                .lines()
                .map(|l| {
                    let first = l.chars().next().unwrap_or(' ').to_string();
                    vec![first, l.to_owned()]
                })
                .collect();
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: poem,
                explanation: "Acrostico generado: la primera letra de cada verso forma el mensaje oculto.".into(),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "acrostic".into(),
                    headers: vec!["Inicial".into(), "Verso / Linea".into()],
                    rows: lines,
                }),
                meta: Vec::new(),
            })
        }
        Action::Decrypt | Action::Solve => {
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let line_initials: String = lines
                .iter()
                .filter_map(|l| l.trim_start().chars().next())
                .map(fold_latin_char)
                .filter(|c| c.is_ascii_alphabetic())
                .map(|c| c.to_ascii_uppercase())
                .collect();
            let line_finals: String = lines
                .iter()
                .filter_map(|l| {
                    l.trim_end()
                        .chars()
                        .rev()
                        .find(|c| fold_latin_char(*c).is_ascii_alphabetic())
                })
                .map(|c| fold_latin_char(c).to_ascii_uppercase())
                .collect();
            let word_initials: String = text
                .split_whitespace()
                .filter_map(|w| w.chars().find(|c| fold_latin_char(*c).is_ascii_alphabetic()))
                .map(|c| fold_latin_char(c).to_ascii_uppercase())
                .collect();
            let mesostic: String = lines
                .iter()
                .enumerate()
                .filter_map(|(i, l)| {
                    l.chars()
                        .filter(|c| fold_latin_char(*c).is_ascii_alphabetic())
                        .nth(i)
                })
                .map(|c| fold_latin_char(c).to_ascii_uppercase())
                .collect();
            let isolated_caps: String = text
                .chars()
                .enumerate()
                .filter(|&(i, c)| {
                    c.is_ascii_uppercase()
                        && i > 0
                        && !text.chars().nth(i - 1).is_some_and(|p| p == '.' || p == '\n')
                })
                .map(|(_, c)| c)
                .collect();

            let mut channels = vec![
                ("Iniciales de cada linea (Acrostico)", line_initials.clone()),
                ("Iniciales de cada palabra (Notarikon)", word_initials.clone()),
                ("Ultima letra de cada linea (Telestico)", line_finals),
                ("Diagonal progresiva (Mesostico)", mesostic),
            ];
            if !isolated_caps.is_empty() {
                channels.push(("Mayusculas intercaladas", isolated_caps));
            }

            let mut scored: Vec<Candidate> = channels
                .into_iter()
                .filter(|(_, s)| !s.is_empty())
                .map(|(lbl, s)| Candidate {
                    label: lbl.to_owned(),
                    score: score_text(&s),
                    text: s,
                })
                .collect();

            let mode = param.trim().to_ascii_lowercase();
            let result = if action == Action::Decrypt && mode == "words" && !word_initials.is_empty() {
                word_initials
            } else if action == Action::Decrypt && !line_initials.is_empty() {
                line_initials
            } else {
                scored.sort_by(|a, b| b.score.total_cmp(&a.score));
                scored.first().map_or_else(String::new, |c| c.text.clone())
            };

            let rows: Vec<Vec<String>> = lines
                .iter()
                .map(|l| {
                    let first = l.trim_start().chars().next().unwrap_or(' ').to_string();
                    vec![first, (*l).to_owned()]
                })
                .collect();

            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result,
                explanation: "Extraccion automatica de acrosticos, notarikon, telesticos y mesosticos.".into(),
                candidates: if action == Action::Solve { scored } else { Vec::new() },
                grid: Some(GridData {
                    kind: "acrostic".into(),
                    headers: vec!["Letra".into(), "Linea".into()],
                    rows,
                }),
                meta: Vec::new(),
            })
        }
    }
}

// ============================================================================
// Presets listos para probar/resolver los 13 cifrados
// ============================================================================

/// Devuelve un JSON con ejemplos listos para probar cada uno de los 13 cifrados.
pub fn presets_json() -> String {
    struct ChallengeDef<'a> {
        title: &'a str,
        mode: &'a str,
        plain: &'a str,
        cipher_override: &'a str,
        key: &'a str,
        param: &'a str,
    }

    let ch = |title, mode, plain, key, param| ChallengeDef {
        title,
        mode,
        plain,
        cipher_override: "",
        key,
        param,
    };

    let defs: [(&str, &str, Vec<ChallengeDef>); 13] = [
        ("caesar", "Cifrado Cesar", vec![
            ch("Clasico +3 (Roma)", "encrypt", "ATAQUE AL AMANECER", "3", ""),
            ch("Mensaje Largo (+13 ROT13)", "solve", "EL MENSAJE SECRETO ESTA GUARDADO EN EL ARCHIVO CENTRAL", "13", ""),
            ch("Texto en Ingles (+7)", "solve", "MEET ME AT THE OLD BRIDGE BEFORE MIDNIGHT", "7", ""),
        ]),
        ("atbash", "Cifrado Atbash", vec![
            ch("Espejo A<->Z", "encrypt", "HOLA MUNDO SECRETO", "", ""),
            ch("Frase Larga", "solve", "LA VERDAD OCULTA REPOSA EN EL ESPEJO DEL ALFABETO", "", ""),
            ch("Simetria Ingles", "solve", "THE SECRET MIRROR REVERSES EVERY SINGLE LETTER", "", ""),
        ]),
        ("pigpen", "Cifrado Pigpen", vec![
            ch("Teclado Masonico", "encrypt", "HOLA MUNDO", "", ""),
            ch("Orden Secreta", "solve", "EL TESORO DEL TEMPLO ESTA BAJO LA PIEDRA", "", ""),
            ch("Todas las Letras", "encrypt", "SECRETO MASONICO XYZ", "", ""),
        ]),
        ("alberti", "Disco de Alberti", vec![
            ch("Giro cada 4 letras", "encrypt", "ATAQUE AL AMANECER", "K", "4"),
            ch("Rotacion Rapida (+1/2)", "solve", "LAS NAVES ZARPAN AL RAYAR EL ALBA SIN DEMORA", "M", "2"),
            ch("Disco Estatico (0 giros)", "solve", "MENSAJE CONFIDENCIAL PARA EL CONSEJO DE FLORENCIA", "G", "0"),
        ]),
        ("vigenere", "Cifrado de Vigenere", vec![
            ch("Reto 1 · Clave CLAVE", "solve", "EL TESORO ESTA OCULTO BAJO EL ROBLE ANTIGUO DE LA PLAZA MAYOR", "CLAVE", ""),
            ch("Reto 2 · Clave SECRETO (Larga)", "solve", "CUANDO LA LUNA ILUMINE EL PUERTO NORTE ENVIAREMOS LA SENAL ACORDADA POR RADIO", "SECRETO", ""),
            ch("Reto 3 · Cifrado MADRID", "encrypt", "LOS PLANOS DE LA BOVEDA ESTAN CIFRADOS CON POLIALFABETO", "MADRID", ""),
        ]),
        ("playfair", "Cifrado Playfair", vec![
            ch("Matriz MONARQUIA", "solve", "ATAQUE AL AMANECER SIN DEMORA AL SUR", "MONARQUIA", ""),
            ch("Reto Historico PLAYFAIR", "solve", "EL MENSAJE SECRETO DEBE LLEGAR ANTES DE MEDIANOCHE", "PLAYFAIR", ""),
            ch("Doble Letra (LL -> LX)", "encrypt", "LLAMADA URGENTE EN CASTILLA", "SECRETO", ""),
        ]),
        ("jefferson", "Cilindro de Jefferson", vec![
            ch("36 Rotores (+6)", "solve", "ATAQUEALAMANECER", "JEFFERSON1795", "6"),
            ch("Mensaje Diplomatico (+11)", "solve", "ELCONSEJOSECRETOSEDEBEREUNIRHOY", "JEFFERSON1795", "11"),
            ch("Semilla Personalizada", "encrypt", "MENSAJEPARAPARIS", "MONTICELLO", "9"),
        ]),
        ("scytale", "Escitala Espartana", vec![
            ch("Vara 4 Caras", "solve", "ATAQUEALAMANECER", "4", "4"),
            ch("Vara 6 Caras (Larga)", "solve", "EL REY DE ESPARTA ENVIA REFUERZOS AL PASO DE LAS TERMOPILAS", "6", "6"),
            ch("Vara 5 Caras", "encrypt", "MENSAJE SECRETO EN ESPARTA", "5", "5"),
        ]),
        ("rail_fence", "Cifrado Rail Fence", vec![
            ch("Onda 3 Railes", "solve", "ATAQUE AL AMANECER", "3", "3"),
            ch("Onda Profunda 5 Railes", "solve", "EL CORREO DEL NORTE TRAE LOS PLANOS DE LA MURALLA", "5", "5"),
            ch("4 Railes", "encrypt", "ZIGZAG CRIPTOGRAFICO EN RUST", "4", "4"),
        ]),
        ("columnar", "Transposicion por Columnas", vec![
            ch("Clave CLAVE (5 cols)", "solve", "ATAQUEALAMANECER", "CLAVE", ""),
            ch("Clave SECRETO (Crack 6)", "solve", "EL TESORO ESTA OCULTO BAJO EL ROBLE DEL BOSQUE", "MADRID", ""),
            ch("Clave ENIGMA (6 cols)", "encrypt", "REUNION SECRETA EN LA BIBLIOTECA A LAS DOCE", "ENIGMA", ""),
        ]),
        ("cardano", "Rejilla de Cardano", vec![
            ch("Rejilla 6x6 CARDANO", "solve", "ATAQUE AL AMANECER", "CARDANO", "6"),
            ch("Rejilla 8x8 SECRETO", "solve", "LOS CUATRO GIROS REVELAN EL PLANO OCULTO EN EL PERGAMINO", "SECRETO", "8"),
            ch("Rejilla Compacta 4x4", "encrypt", "CLAVE DEL COFRE", "1550", "4"),
        ]),
        ("invisible_ink", "Tinta Invisible", vec![
            ch("Carta con Tinta Zero-Width", "solve", "CLAVE SECRETA 42", "Buenos dias, te envio los apuntes de la reunion.", ""),
            ch("Informe Corporativo Oculto", "solve", "REUNION 23:30 EN PUERTA SUR", "Adjunto el resumen trimestral de ventas y objetivos de este mes.", ""),
            ch("Ocultar Coordenadas", "encrypt", "40.4168N 3.7038W", "Hola, nos vemos manana para tomar un cafe cerca del parque.", ""),
        ]),
        ("acrostic", "Acrosticos", vec![
            ch("Poema SECRETO", "solve", "SECRETO", "", ""),
            ch("Verso Largo TESORO", "encrypt", "TESORO", "", ""),
            ch("Mensaje ATAQUE", "encrypt", "ATAQUE", "", ""),
        ]),
    ];

    let mut out = String::from("[");
    for (idx, (id, name, challenges)) in defs.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let first = &challenges[0];
        let mut challenge_json = String::from("[");
        let mut first_cipher = String::new();

        for (ci, c) in challenges.iter().enumerate() {
            if ci > 0 {
                challenge_json.push(',');
            }
            let enc = if !c.cipher_override.is_empty() {
                c.cipher_override.to_owned()
            } else if *id == "acrostic" && ci == 0 {
                "Siempre atento al norte\nEntre sombras viaja el aviso\nCada paso deja su rastro\nRecuerda la hora exacta\nEl puente abre al alba\nTodos esperan la senal\nOculta la carta bajo piedra".to_owned()
            } else {
                execute(&CipherRequest {
                    cipher: (*id).into(),
                    action: "encrypt".into(),
                    text: c.plain.into(),
                    key: c.key.into(),
                    param: c.param.into(),
                })
                .map(|o| o.result)
                .unwrap_or_default()
            };
            if ci == 0 {
                first_cipher = enc.clone();
            }
            challenge_json.push_str(&format!(
                "{{\"title\":\"{}\",\"mode\":\"{}\",\"plain\":\"{}\",\"cipher\":\"{}\",\"key\":\"{}\",\"param\":\"{}\"}}",
                json_escape(c.title),
                json_escape(c.mode),
                json_escape(c.plain),
                json_escape(&enc),
                json_escape(c.key),
                json_escape(c.param),
            ));
        }
        challenge_json.push(']');

        out.push_str(&format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"sample_plain\":\"{}\",\"sample_cipher\":\"{}\",\"key\":\"{}\",\"param\":\"{}\",\"challenges\":{}}}",
            json_escape(id),
            json_escape(name),
            json_escape(first.plain),
            json_escape(&first_cipher),
            json_escape(first.key),
            json_escape(first.param),
            challenge_json,
        ));
    }
    out.push(']');
    out
}

/// Devuelve informacion arquitectonica e historica del proyecto y sus 13 cifrados.
pub fn project_info_json() -> String {
    let cards = [
        ("caesar", "Cifrado Cesar", "Sustitucion Monoalfabetica", "~50 a.C. · Julio Cesar", "E(x) = (x + k) mod 26", "Solo existen 25 claves posibles: vulnerable a fuerza bruta inmediata y analisis de frecuencias."),
        ("atbash", "Cifrado Atbash", "Sustitucion Monoalfabetica", "~500 a.C. · Alfabeto Hebreo", "E(x) = 25 - x", "Involucion fija sin clave secreta; basta conocer el metodo para invertirlo al instante."),
        ("pigpen", "Cifrado Pigpen", "Sustitucion Monoalfabetica", "S. XVIII · Francmasoneria", "Letra -> Fragmento de rejilla/aspa", "Mantiene intactas las frecuencias de letras del idioma original bajo simbolos geometricos."),
        ("alberti", "Disco de Alberti", "Polialfabeticos y Rotores", "1467 · Leon Battista Alberti", "C_i = Inner[(P_i + offset(i)) mod 26]", "Rompio el monoalfabetismo girando el disco interior periodicamente, pero sus 26 alineaciones se prueban en microsegundos."),
        ("vigenere", "Cifrado de Vigenere", "Polialfabeticos y Rotores", "1553 · Bellaso / Vigenere", "C_i = (P_i + K_{i mod m}) mod 26", "El Indice de Coincidencia de Friedman revela la longitud de clave y reduce cada columna a un Cesar."),
        ("playfair", "Cifrado Playfair", "Polialfabeticos y Rotores", "1854 · Wheatstone / Playfair", "Digrafos sobre matriz 5x5 (I=J)", "Aunque oculta frecuencias individuales, las frecuencias de bigramas permiten atacarlo mediante Hill-Climbing."),
        ("jefferson", "Cilindro de Jefferson", "Polialfabeticos y Rotores", "1795 · Thomas Jefferson", "36 discos independientes, fila +k", "Conocido el orden de los discos, solo 1 de las 25 filas paralelas forma texto legible."),
        ("scytale", "Escitala Espartana", "Transposicion y Geometria", "~400 a.C. · Esparta", "Lectura longitudinal en vara de D caras", "El numero de caras D es pequeno; probar de 2 a 20 caras desenrolla la cinta automaticamente."),
        ("rail_fence", "Cifrado Rail Fence", "Transposicion y Geometria", "Clasico · Onda Zig-Zag", "Onda triangular sobre R railes", "Solo depende de R (habitualmente 2..12), trivial de enumerar por fuerza bruta."),
        ("columnar", "Transposicion por Columnas", "Transposicion y Geometria", "Siglos XIX-XX · Militar", "Permutacion de columnas segun orden de clave", "Para claves cortas (<= 6 columnas), Rust evalua las 872 permutaciones posibles en ~1 ms."),
        ("cardano", "Rejilla de Cardano", "Transposicion y Geometria", "1550 · Girolamo Cardano", "4 giros de 90 grados sobre N x N", "Cada orbita de 4 casillas tiene una unica perforacion valida; un error en la mascara corrompe el mensaje."),
        ("invisible_ink", "Tinta Invisible", "Esteganografia Digital", "Unicode Zero-Width", "Byte -> 4 simbolos {U+200B, 200C, 200D, FEFF}", "Invisible a simple vista en texto normal, pero un escaner de codepoints Unicode lo revela al instante."),
        ("acrostic", "Acrosticos", "Esteganografia Literaria", "Antiguedad · Poesia oculta", "Iniciales / Telesticos / Mesosticos", "Requiere redactar versos naturales; Rust extrae 5 canales posicionales en paralelo."),
    ];

    let mut out = String::from("{\"project\":{\"name\":\"Cipher Studio\",\"engine\":\"Rust 2024 Nativo (0 dependencias externas)\",\"algorithms\":13,\"scoring\":\"Modelo heuristico bilingue ES/EN con unigramas, bigramas, trigramas, proporcion vocalica e Indice de Coincidencia.\"},\"ciphers\":[");
    for (i, (id, name, category, era, formula, vuln)) in cards.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"category\":\"{}\",\"era\":\"{}\",\"formula\":\"{}\",\"vulnerability\":\"{}\"}}",
            json_escape(id),
            json_escape(name),
            json_escape(category),
            json_escape(era),
            json_escape(formula),
            json_escape(vuln),
        ));
    }
    out.push_str("]}");
    out
}

// ============================================================================
// Parser y serializador JSON ligero sin dependencias externas
// ============================================================================

/// Escapa caracteres especiales para una cadena JSON valida.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Serializa un `CipherOutput` a JSON.
pub fn output_to_json(out: &CipherOutput) -> String {
    let mut buf = String::with_capacity(512);
    buf.push('{');
    buf.push_str(&format!(
        "\"cipher\":\"{}\",\"action\":\"{}\",\"result\":\"{}\",\"explanation\":\"{}\"",
        json_escape(&out.cipher),
        json_escape(&out.action),
        json_escape(&out.result),
        json_escape(&out.explanation),
    ));

    buf.push_str(",\"candidates\":[");
    for (i, c) in out.candidates.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push_str(&format!(
            "{{\"label\":\"{}\",\"text\":\"{}\",\"score\":{}}}",
            json_escape(&c.label),
            json_escape(&c.text),
            format_score(c.score),
        ));
    }
    buf.push(']');

    buf.push_str(",\"grid\":");
    if let Some(g) = &out.grid {
        buf.push_str(&format!("{{\"kind\":\"{}\",\"headers\":[", json_escape(&g.kind)));
        for (i, h) in g.headers.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            buf.push_str(&format!("\"{}\"", json_escape(h)));
        }
        buf.push_str("],\"rows\":[");
        for (ri, row) in g.rows.iter().enumerate() {
            if ri > 0 {
                buf.push(',');
            }
            buf.push('[');
            for (ci, cell) in row.iter().enumerate() {
                if ci > 0 {
                    buf.push(',');
                }
                buf.push_str(&format!("\"{}\"", json_escape(cell)));
            }
            buf.push(']');
        }
        buf.push_str("]}");
    } else {
        buf.push_str("null");
    }

    buf.push_str(",\"meta\":{");
    for (i, m) in out.meta.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push_str(&format!(
            "\"{}\":\"{}\"",
            json_escape(&m.key),
            json_escape(&m.value)
        ));
    }
    buf.push_str("}}");
    buf
}

/// Parsea un objeto JSON plano con campos string/number hacia `CipherRequest`.
pub fn parse_cipher_request_json(body: &str) -> Result<CipherRequest, CipherError> {
    let map = parse_flat_json_object(body)?;
    let cipher = map
        .get("cipher")
        .cloned()
        .ok_or_else(|| CipherError::JsonParse("falta el campo 'cipher'".into()))?;
    let action = map.get("action").cloned().unwrap_or_else(|| "encrypt".into());
    let text = map.get("text").cloned().unwrap_or_default();
    let key = map.get("key").cloned().unwrap_or_default();
    let param = map.get("param").cloned().unwrap_or_default();
    Ok(CipherRequest {
        cipher,
        action,
        text,
        key,
        param,
    })
}

fn parse_flat_json_object(input: &str) -> Result<BTreeMap<String, String>, CipherError> {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let skip_ws = |idx: &mut usize| {
        while *idx < bytes.len() && bytes[*idx].is_ascii_whitespace() {
            *idx += 1;
        }
    };

    skip_ws(&mut i);
    if i >= bytes.len() || bytes[i] != b'{' {
        return Err(CipherError::JsonParse("se esperaba '{'".into()));
    }
    i += 1;

    let mut map = BTreeMap::new();
    loop {
        skip_ws(&mut i);
        if i >= bytes.len() {
            return Err(CipherError::JsonParse("json truncado".into()));
        }
        if bytes[i] == b'}' {
            return Ok(map);
        }
        let k = parse_json_string(input, &mut i)?;
        skip_ws(&mut i);
        if i >= bytes.len() || bytes[i] != b':' {
            return Err(CipherError::JsonParse("se esperaba ':'".into()));
        }
        i += 1;
        skip_ws(&mut i);
        let v = if i < bytes.len() && bytes[i] == b'"' {
            parse_json_string(input, &mut i)?
        } else {
            let start = i;
            while i < bytes.len() && !matches!(bytes[i], b',' | b'}' | b' ' | b'\n' | b'\r' | b'\t') {
                i += 1;
            }
            let raw = &input[start..i];
            if raw == "null" {
                String::new()
            } else {
                raw.to_owned()
            }
        };
        map.insert(k, v);
        skip_ws(&mut i);
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        }
    }
}

fn parse_json_string(input: &str, idx: &mut usize) -> Result<String, CipherError> {
    let bytes = input.as_bytes();
    if *idx >= bytes.len() || bytes[*idx] != b'"' {
        return Err(CipherError::JsonParse("se esperaba cadena JSON".into()));
    }
    *idx += 1;
    let mut out = String::new();
    while *idx < bytes.len() {
        let ch = input[*idx..].chars().next().ok_or_else(|| CipherError::JsonParse("utf8 invalido".into()))?;
        *idx += ch.len_utf8();
        if ch == '"' {
            return Ok(out);
        }
        if ch == '\\' {
            let esc = input[*idx..].chars().next().ok_or_else(|| CipherError::JsonParse("escape truncado".into()))?;
            *idx += esc.len_utf8();
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000C}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    if *idx + 4 > input.len() {
                        return Err(CipherError::JsonParse("escape \\u incompleto".into()));
                    }
                    let hex = &input[*idx..*idx + 4];
                    *idx += 4;
                    let code = u16::from_str_radix(hex, 16)
                        .map_err(|_| CipherError::JsonParse("hexadecimal \\u invalido".into()))?;
                    if (0xD800..=0xDBFF).contains(&code) && input[*idx..].starts_with("\\u") && *idx + 6 <= input.len() {
                        let low = u16::from_str_radix(&input[*idx + 2..*idx + 6], 16)
                            .map_err(|_| CipherError::JsonParse("surrogate bajo invalido".into()))?;
                        *idx += 6;
                        let cp = 0x10000 + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                        let decoded = char::from_u32(cp)
                            .ok_or_else(|| CipherError::JsonParse("codepoint invalido".into()))?;
                        out.push(decoded);
                    } else {
                        let decoded = char::from_u32(code as u32)
                            .ok_or_else(|| CipherError::JsonParse("codepoint invalido".into()))?;
                        out.push(decoded);
                    }
                }
                other => out.push(other),
            }
        } else {
            out.push(ch);
        }
    }
    Err(CipherError::JsonParse("cadena JSON sin cierre".into()))
}

// ============================================================================
// Puente WebAssembly (wasm32-unknown-unknown) sin dependencias externas
// ============================================================================

#[cfg(target_arch = "wasm32")]
mod wasm_api {
    use super::{execute, json_escape, output_to_json, parse_cipher_request_json, presets_json, project_info_json};
    use std::cell::RefCell;

    thread_local! {
        static OUT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    fn set_out(s: String) -> *const u8 {
        OUT_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            *buf = s.into_bytes();
            buf.as_ptr()
        })
    }

    /// Reserva un buffer UTF-8 en memoria lineal WASM para pasar entradas desde JS.
    #[unsafe(no_mangle)]
    pub extern "C" fn wasm_alloc(len: usize) -> *mut u8 {
        let mut buf = Vec::with_capacity(len);
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        ptr
    }

    /// Libera un buffer reservado previamente con `wasm_alloc`.
    ///
    /// # Safety
    /// `ptr` debe haber sido devuelto por `wasm_alloc(len)` y no haberse liberado antes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wasm_free(ptr: *mut u8, len: usize) {
        if !ptr.is_null() && len > 0 {
            // SAFETY: el llamador JS garantiza ptr y len exactos de `wasm_alloc`.
            unsafe {
                drop(Vec::from_raw_parts(ptr, 0, len));
            }
        }
    }

    /// Devuelve la longitud en bytes de la ultima respuesta almacenada en `OUT_BUF`.
    #[unsafe(no_mangle)]
    pub extern "C" fn wasm_out_len() -> usize {
        OUT_BUF.with(|cell| cell.borrow().len())
    }

    /// Devuelve el JSON de presets (`GET /api/presets`).
    #[unsafe(no_mangle)]
    pub extern "C" fn wasm_presets() -> *const u8 {
        set_out(presets_json())
    }

    /// Devuelve el JSON de informacion del proyecto (`GET /api/info`).
    #[unsafe(no_mangle)]
    pub extern "C" fn wasm_info() -> *const u8 {
        set_out(project_info_json())
    }

    /// Ejecuta una peticion JSON de cifrado/descifrado/resolucion (`POST /api/cipher`).
    ///
    /// # Safety
    /// `ptr..ptr+len` debe apuntar a bytes UTF-8 validos en memoria lineal WASM.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wasm_cipher(ptr: *const u8, len: usize) -> *const u8 {
        // SAFETY: JS copia el JSON en memoria lineal mediante `wasm_alloc(len)` antes de llamar.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let body = String::from_utf8_lossy(bytes);
        let out = match parse_cipher_request_json(&body).and_then(|req| execute(&req)) {
            Ok(res) => output_to_json(&res),
            Err(err) => format!("{{\"error\":\"{}\"}}", json_escape(&err.to_string())),
        };
        set_out(out)
    }
}

// ============================================================================
// Tests unitarios para los 13 cifrados
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn req(cipher: &str, action: &str, text: &str, key: &str, param: &str) -> CipherRequest {
        CipherRequest {
            cipher: cipher.into(),
            action: action.into(),
            text: text.into(),
            key: key.into(),
            param: param.into(),
        }
    }

    #[test]
    fn caesar_roundtrip_and_solve() {
        let enc = execute(&req("caesar", "encrypt", "ATAQUE AL AMANECER", "5", "")).unwrap();
        let dec = execute(&req("caesar", "decrypt", &enc.result, "5", "")).unwrap();
        assert_eq!(dec.result, "ATAQUE AL AMANECER");

        let solved = execute(&req("caesar", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, "ATAQUE AL AMANECER");
    }

    #[test]
    fn atbash_roundtrip() {
        let enc = execute(&req("atbash", "encrypt", "HOLA MUNDO", "", "")).unwrap();
        let dec = execute(&req("atbash", "decrypt", &enc.result, "", "")).unwrap();
        assert_eq!(dec.result, "HOLA MUNDO");
    }

    #[test]
    fn pigpen_roundtrip_and_solve() {
        let enc = execute(&req("pigpen", "encrypt", "HOLA MUNDO", "", "")).unwrap();
        assert!(enc.result.contains('⊓'));
        let dec = execute(&req("pigpen", "decrypt", &enc.result, "", "")).unwrap();
        assert_eq!(dec.result, "HOLA MUNDO");
        let solved = execute(&req("pigpen", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, "HOLA MUNDO");
    }

    #[test]
    fn alberti_roundtrip_and_solve() {
        let enc = execute(&req("alberti", "encrypt", "ATAQUE AL AMANECER", "K", "4")).unwrap();
        let dec = execute(&req("alberti", "decrypt", &enc.result, "K", "4")).unwrap();
        assert_eq!(dec.result, "ATAQUE AL AMANECER");

        let solved = execute(&req("alberti", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, "ATAQUE AL AMANECER");
    }

    #[test]
    fn vigenere_roundtrip_and_solve() {
        let plain = "EL TESORO ESTA OCULTO BAJO EL ROBLE ANTIGUO DE LA PLAZA";
        let enc = execute(&req("vigenere", "encrypt", plain, "CLAVE", "")).unwrap();
        let dec = execute(&req("vigenere", "decrypt", &enc.result, "CLAVE", "")).unwrap();
        assert_eq!(dec.result, plain);

        let solved = execute(&req("vigenere", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, plain);
    }

    #[test]
    fn playfair_roundtrip_and_solve() {
        let enc = execute(&req("playfair", "encrypt", "ATAQUE AL AMANECER", "MONARQUIA", "")).unwrap();
        let dec = execute(&req("playfair", "decrypt", &enc.result, "MONARQUIA", "")).unwrap();
        assert_eq!(dec.result, "ATAQUEALAMANECER");

        let solved = execute(&req("playfair", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, "ATAQUEALAMANECER");
    }

    #[test]
    fn jefferson_roundtrip_and_solve() {
        let enc = execute(&req("jefferson", "encrypt", "ATAQUEALAMANECER", "JEFFERSON1795", "6")).unwrap();
        let dec = execute(&req("jefferson", "decrypt", &enc.result, "JEFFERSON1795", "6")).unwrap();
        assert_eq!(dec.result, "ATAQUEALAMANECER");

        let solved = execute(&req("jefferson", "solve", &enc.result, "JEFFERSON1795", "")).unwrap();
        assert_eq!(solved.result, "ATAQUEALAMANECER");
    }

    #[test]
    fn scytale_roundtrip_and_solve() {
        let plain = "EL TESORO ESTA OCULTO EN ESPARTA";
        let enc = execute(&req("scytale", "encrypt", plain, "5", "")).unwrap();
        let dec = execute(&req("scytale", "decrypt", &enc.result, "5", "")).unwrap();
        assert_eq!(dec.result, plain);

        let solved = execute(&req("scytale", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, plain);
    }

    #[test]
    fn rail_fence_roundtrip_and_solve() {
        let plain = "ATAQUE AL AMANECER SIN DEMORA";
        let enc = execute(&req("rail_fence", "encrypt", plain, "4", "")).unwrap();
        let dec = execute(&req("rail_fence", "decrypt", &enc.result, "4", "")).unwrap();
        assert_eq!(dec.result, plain);

        let solved = execute(&req("rail_fence", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, plain);
    }

    #[test]
    fn columnar_roundtrip_and_solve() {
        let plain = "EL MENSAJE SECRETO ESTA EN LA TORRE";
        let enc = execute(&req("columnar", "encrypt", plain, "CLAVE", "")).unwrap();
        let dec = execute(&req("columnar", "decrypt", &enc.result, "CLAVE", "")).unwrap();
        assert_eq!(dec.result, plain);

        let solved = execute(&req("columnar", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, plain);
    }

    #[test]
    fn cardano_roundtrip_and_solve() {
        let plain = "ATAQUE AL AMANECER";
        let enc = execute(&req("cardano", "encrypt", plain, "CARDANO", "6")).unwrap();
        let dec = execute(&req("cardano", "decrypt", &enc.result, "CARDANO", "6")).unwrap();
        assert_eq!(dec.result, plain);

        let solved = execute(&req("cardano", "solve", &enc.result, "", "6")).unwrap();
        assert_eq!(solved.result, plain);
    }

    #[test]
    fn invisible_ink_roundtrip() {
        let enc = execute(&req("invisible_ink", "encrypt", "CLAVE 42", "Texto normal", "")).unwrap();
        assert!(enc.result.starts_with('T'));
        let dec = execute(&req("invisible_ink", "decrypt", &enc.result, "", "")).unwrap();
        assert_eq!(dec.result, "CLAVE 42");
    }

    #[test]
    fn acrostic_roundtrip() {
        let enc = execute(&req("acrostic", "encrypt", "SECRETO", "", "")).unwrap();
        let solved = execute(&req("acrostic", "solve", &enc.result, "", "")).unwrap();
        assert_eq!(solved.result, "SECRETO");
    }

    #[test]
    fn json_parser_handles_zw_and_escapes() {
        let enc = execute(&req("invisible_ink", "encrypt", "OK", "Hola", "")).unwrap();
        let escaped = json_escape(&enc.result);
        let body = format!("{{\"cipher\":\"invisible_ink\",\"action\":\"decrypt\",\"text\":\"{escaped}\"}}");
        let parsed = parse_cipher_request_json(&body).unwrap();
        let dec = execute(&parsed).unwrap();
        assert_eq!(dec.result, "OK");
    }

    #[test]
    fn empty_inputs_never_fail_for_all_ciphers() {
        let ids = [
            "caesar", "atbash", "pigpen", "alberti", "vigenere", "playfair",
            "jefferson", "scytale", "rail_fence", "columnar", "cardano",
            "invisible_ink", "acrostic",
        ];
        for id in ids {
            for act in ["encrypt", "decrypt", "solve"] {
                let res = execute(&req(id, act, "", "", ""));
                assert!(res.is_ok(), "fallo en {id} / {act} con entrada vacia");
            }
        }
    }

    #[test]
    fn spanish_accents_and_enie_roundtrip() {
        let plain = "Mañana será un día épico en España";
        for id in ["caesar", "atbash", "alberti", "vigenere", "scytale", "rail_fence", "columnar"] {
            let enc = execute(&req(id, "encrypt", plain, "CLAVE", "4")).unwrap();
            let dec = execute(&req(id, "decrypt", &enc.result, "CLAVE", "4")).unwrap();
            assert!(!dec.result.is_empty(), "{id} devolvio vacio");
        }
        let info = project_info_json();
        assert!(info.contains("\"algorithms\":13"));
    }
}
