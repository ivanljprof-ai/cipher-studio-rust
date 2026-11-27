//! Algoritmos criptograficos modernos de bloque y hash en Rust puro (0 dependencias):
//! DES (FIPS 46-3), 3DES (EDE), IDEA (128-bit), AES-128/192/256 (FIPS 197) y MD5 (RFC 1321).

use crate::{Action, Candidate, CipherError, CipherOutput, GridData, MetaEntry, score_text};

// ============================================================================
// Utilidades compartidas Hex, Claves y PKCS#7
// ============================================================================

/// Codifica bytes a hexadecimal en mayusculas.
pub fn hex_encode_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Codifica bytes a hexadecimal en minusculas.
pub fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodifica una cadena hexadecimal ignorando espacios.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, CipherError> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(CipherError::InvalidInput("la cadena hexadecimal debe tener longitud par".into()));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|_| CipherError::InvalidInput("caracter hexadecimal invalido".into()))?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_key_bytes(key: &str, target_len: usize, default_key: &[u8]) -> Vec<u8> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return default_key.to_vec();
    }
    let hex_cand = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_cand.len() == target_len * 2
        && hex_cand.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(decoded) = hex_decode(hex_cand)
    {
        return decoded;
    }
    let raw = trimmed.as_bytes();
    (0..target_len).map(|i| raw[i % raw.len()]).collect()
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.resize(data.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CipherError> {
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CipherError::InvalidInput("longitud de bloque cifrado invalida".into()));
    }
    let pad = *data.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return Err(CipherError::InvalidInput("padding PKCS#7 invalido (clave incorrecta?)".into()));
    }
    if !data[data.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Err(CipherError::InvalidInput("padding PKCS#7 corrupto (clave incorrecta?)".into()));
    }
    Ok(data[..data.len() - pad].to_vec())
}

fn bytes_to_readable(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => hex_encode_upper(bytes),
    }
}

// ============================================================================
// 14 & 15. DES y 3DES (FIPS 46-3 / NIST SP 800-67)
// ============================================================================

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_SBOX: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn permute_bits(val: u64, table: &[u8], in_bits: usize) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        let bit = (val >> (in_bits - pos as usize)) & 1;
        out = (out << 1) | bit;
    }
    out
}

fn des_subkeys(key64: u64) -> [u64; 16] {
    let k56 = permute_bits(key64, &DES_PC1, 64);
    let mut c = (k56 >> 28) & 0x0FFF_FFFF;
    let mut d = k56 & 0x0FFF_FFFF;
    let mut keys = [0u64; 16];
    for (i, &sh) in DES_SHIFTS.iter().enumerate() {
        c = ((c << sh) | (c >> (28 - sh))) & 0x0FFF_FFFF;
        d = ((d << sh) | (d >> (28 - sh))) & 0x0FFF_FFFF;
        let cd = (c << 28) | d;
        keys[i] = permute_bits(cd, &DES_PC2, 56);
    }
    keys
}

fn des_feistel(r: u32, subkey: u64) -> u32 {
    let expanded = permute_bits(r as u64, &DES_E, 32) ^ subkey;
    let mut s_out = 0u32;
    for (box_idx, sbox) in DES_SBOX.iter().enumerate() {
        let six = ((expanded >> (42 - box_idx * 6)) & 0x3F) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let col = (six >> 1) & 0x0F;
        s_out = (s_out << 4) | (sbox[row][col] as u32);
    }
    permute_bits(s_out as u64, &DES_P, 32) as u32
}

/// Cifra o descifra un bloque de 8 bytes con DES devolviendo tambien la traza de 16 rondas.
pub fn des_block_with_trace(block: [u8; 8], key: [u8; 8], encrypt: bool) -> ([u8; 8], Vec<[String; 4]>) {
    let val = u64::from_be_bytes(block);
    let k64 = u64::from_be_bytes(key);
    let keys = des_subkeys(k64);
    let ip = permute_bits(val, &DES_IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    let mut trace = Vec::with_capacity(16);

    for round in 0..16 {
        let k = if encrypt { keys[round] } else { keys[15 - round] };
        let f = des_feistel(r, k);
        let next_r = l ^ f;
        l = r;
        r = next_r;
        trace.push([
            format!("R{}", round + 1),
            format!("{l:08X}"),
            format!("{r:08X}"),
            format!("{k:012X}"),
        ]);
    }

    let pre_fp = ((r as u64) << 32) | (l as u64);
    let fp = permute_bits(pre_fp, &DES_FP, 64);
    (fp.to_be_bytes(), trace)
}

fn des_transform_bytes(data: &[u8], key: [u8; 8], encrypt: bool) -> (Vec<u8>, Vec<[String; 4]>) {
    let mut out = Vec::with_capacity(data.len());
    let mut first_trace = Vec::new();
    for (idx, chunk) in data.chunks_exact(8).enumerate() {
        let mut blk = [0u8; 8];
        blk.copy_from_slice(chunk);
        let (res, tr) = des_block_with_trace(blk, key, encrypt);
        if idx == 0 {
            first_trace = tr;
        }
        out.extend_from_slice(&res);
    }
    (out, first_trace)
}

pub(crate) fn run_des(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let key_vec = parse_key_bytes(key, 8, b"CLAVE123");
    let mut key_arr = [0u8; 8];
    key_arr.copy_from_slice(&key_vec);

    match action {
        Action::Encrypt => {
            let padded = pkcs7_pad(text.as_bytes(), 8);
            let (ct, trace) = des_transform_bytes(&padded, key_arr, true);
            let rows = trace.into_iter().map(|r| r.to_vec()).collect();
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: hex_encode_upper(&ct),
                explanation: format!(
                    "DES (64 bits, 16 rondas Feistel, PKCS#7) con clave {} ({} bloques).",
                    hex_encode_upper(&key_arr),
                    ct.len() / 8
                ),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "feistel".into(),
                    headers: vec!["Ronda".into(), "L (32-bit)".into(), "R (32-bit)".into(), "Subclave K".into()],
                    rows,
                }),
                meta: vec![MetaEntry { key: "key_hex".into(), value: hex_encode_upper(&key_arr) }],
            })
        }
        Action::Decrypt => {
            if text.trim().is_empty() {
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "Introduce bytes hexadecimales cifrados con DES para descifrar.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            let ct = hex_decode(text)?;
            let (pt_padded, trace) = des_transform_bytes(&ct, key_arr, false);
            let pt = pkcs7_unpad(&pt_padded, 8)?;
            let rows = trace.into_iter().map(|r| r.to_vec()).collect();
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: bytes_to_readable(&pt),
                explanation: format!("Descifrado DES completado con clave {}.", hex_encode_upper(&key_arr)),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "feistel".into(),
                    headers: vec!["Ronda".into(), "L (32-bit)".into(), "R (32-bit)".into(), "Subclave K".into()],
                    rows,
                }),
                meta: Vec::new(),
            })
        }
        Action::Solve => {
            if text.trim().is_empty() {
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "Introduce texto cifrado hexadecimal DES para probar claves.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            let ct = hex_decode(text)?;
            let mut candidates_keys = Vec::new();
            if !key.trim().is_empty() {
                candidates_keys.push((format!("Clave usuario '{key}'"), key_arr));
            }
            for kw in ["CLAVE123", "SECRETO1", "12345678", "PASSWORD", "133457799BBCDFF1", "0123456789ABCDEF", "DESKEY01", "ADMIN123"] {
                let kv = parse_key_bytes(kw, 8, b"CLAVE123");
                let mut ka = [0u8; 8];
                ka.copy_from_slice(&kv);
                candidates_keys.push((format!("Clave '{kw}'"), ka));
            }

            let mut ranked: Vec<(String, String, f64, Vec<[String; 4]>)> = Vec::new();
            for (lbl, ka) in candidates_keys {
                let (pt_pad, tr) = des_transform_bytes(&ct, ka, false);
                if let Ok(pt) = pkcs7_unpad(&pt_pad, 8)
                    && let Ok(s) = std::str::from_utf8(&pt)
                {
                    ranked.push((lbl, s.to_owned(), score_text(s), tr));
                }
            }
            ranked.sort_by(|a, b| b.2.total_cmp(&a.2));
            let (res, expl, rows) = if let Some((lbl, txt, _, tr)) = ranked.first() {
                (
                    txt.clone(),
                    format!("Auditoria DES sobre claves conocidas: coincidencia valida con {lbl}."),
                    tr.iter().map(|r| r.to_vec()).collect(),
                )
            } else {
                (
                    String::new(),
                    "DES usa 2^56 claves: sin la clave correcta en diccionario no es invertible.".into(),
                    Vec::new(),
                )
            };
            let cands = ranked
                .into_iter()
                .map(|(label, text, score, _)| Candidate { label, text, score })
                .collect();
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: res,
                explanation: expl,
                candidates: cands,
                grid: if rows.is_empty() {
                    None
                } else {
                    Some(GridData {
                        kind: "feistel".into(),
                        headers: vec!["Ronda".into(), "L (32-bit)".into(), "R (32-bit)".into(), "Subclave K".into()],
                        rows,
                    })
                },
                meta: Vec::new(),
            })
        }
    }
}

fn split_3des_keys(key: &str) -> ([u8; 8], [u8; 8], [u8; 8]) {
    let trimmed = key.trim();
    let hex_cand = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let raw = if hex_cand.len() == 32 && hex_cand.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut k = hex_decode(hex_cand).unwrap_or_else(|_| b"CLAVE123SECRETO1".to_vec());
        let k1 = k[..8].to_vec();
        k.extend_from_slice(&k1);
        k
    } else {
        parse_key_bytes(key, 24, b"CLAVE123SECRETO1TRIPLEDS")
    };
    let mut k1 = [0u8; 8];
    let mut k2 = [0u8; 8];
    let mut k3 = [0u8; 8];
    k1.copy_from_slice(&raw[0..8]);
    k2.copy_from_slice(&raw[8..16]);
    k3.copy_from_slice(&raw[16..24]);
    (k1, k2, k3)
}

pub(crate) fn run_triple_des(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let (k1, k2, k3) = split_3des_keys(key);
    match action {
        Action::Encrypt => {
            let padded = pkcs7_pad(text.as_bytes(), 8);
            let (s1, _) = des_transform_bytes(&padded, k1, true);
            let (s2, _) = des_transform_bytes(&s1, k2, false);
            let (s3, _) = des_transform_bytes(&s2, k3, true);
            let b0 = hex_encode_upper(&padded[..8.min(padded.len())]);
            let b1 = hex_encode_upper(&s1[..8.min(s1.len())]);
            let b2 = hex_encode_upper(&s2[..8.min(s2.len())]);
            let b3 = hex_encode_upper(&s3[..8.min(s3.len())]);
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: hex_encode_upper(&s3),
                explanation: "Triple DES (3DES-EDE, 168 bits efectivos): C = E(K3, D(K2, E(K1, P))).".into(),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "pipeline".into(),
                    headers: vec!["Etapa".into(), "Operacion".into(), "Bloque 1 (64-bit)".into()],
                    rows: vec![
                        vec!["Entrada".into(), "PKCS#7".into(), b0],
                        vec!["Etapa 1".into(), format!("E(K1={})", hex_encode_upper(&k1)), b1],
                        vec!["Etapa 2".into(), format!("D(K2={})", hex_encode_upper(&k2)), b2],
                        vec!["Etapa 3".into(), format!("E(K3={})", hex_encode_upper(&k3)), b3],
                    ],
                }),
                meta: Vec::new(),
            })
        }
        Action::Decrypt | Action::Solve => {
            if text.trim().is_empty() {
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "Introduce bytes hexadecimales cifrados con 3DES para descifrar.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            let ct = hex_decode(text)?;
            let mut try_keys = vec![(format!("Clave '{}'", if key.trim().is_empty() { "default" } else { key.trim() }), (k1, k2, k3))];
            if action == Action::Solve {
                for kw in ["CLAVE123SECRETO1TRIPLEDS", "3DES-SECRET-KEY-24BYTES!", "PASSWORD12345678ABCDEFGH"] {
                    try_keys.push((format!("Diccionario '{kw}'"), split_3des_keys(kw)));
                }
            }
            let mut ranked = Vec::new();
            for (lbl, (a, b, c)) in try_keys {
                let (s1, _) = des_transform_bytes(&ct, c, false);
                let (s2, _) = des_transform_bytes(&s1, b, true);
                let (s3, _) = des_transform_bytes(&s2, a, false);
                if let Ok(pt) = pkcs7_unpad(&s3, 8) {
                    let txt = bytes_to_readable(&pt);
                    ranked.push((lbl, txt.clone(), score_text(&txt), s1, s2, s3));
                }
            }
            if ranked.is_empty() {
                return Err(CipherError::InvalidInput("no se pudo descifrar 3DES con la clave indicada".into()));
            }
            if action == Action::Solve {
                ranked.sort_by(|a, b| b.2.total_cmp(&a.2));
            }
            let (_, best_txt, _, s1, s2, s3) = ranked[0].clone();
            let cands = if action == Action::Solve {
                ranked.into_iter().map(|(label, text, score, _, _, _)| Candidate { label, text, score }).collect()
            } else {
                Vec::new()
            };
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: best_txt,
                explanation: "Descifrado 3DES-EDE inverso: P = D(K1, E(K2, D(K3, C))).".into(),
                candidates: cands,
                grid: Some(GridData {
                    kind: "pipeline".into(),
                    headers: vec!["Etapa".into(), "Operacion".into(), "Bloque 1 (64-bit)".into()],
                    rows: vec![
                        vec!["Entrada".into(), "Cifrado".into(), hex_encode_upper(&ct[..8.min(ct.len())])],
                        vec!["Etapa 1".into(), "D(K3)".into(), hex_encode_upper(&s1[..8.min(s1.len())])],
                        vec!["Etapa 2".into(), "E(K2)".into(), hex_encode_upper(&s2[..8.min(s2.len())])],
                        vec!["Etapa 3".into(), "D(K1)".into(), hex_encode_upper(&s3[..8.min(s3.len())])],
                    ],
                }),
                meta: Vec::new(),
            })
        }
    }
}

// ============================================================================
// 16. IDEA (International Data Encryption Algorithm · 128-bit key, 64-bit blk)
// ============================================================================

fn idea_mul(a: u16, b: u16) -> u16 {
    let x = if a == 0 { 65536u64 } else { a as u64 };
    let y = if b == 0 { 65536u64 } else { b as u64 };
    let prod = (x * y) % 65537u64;
    if prod == 65536 { 0 } else { prod as u16 }
}

fn idea_inv(a: u16) -> u16 {
    if a <= 1 {
        return a;
    }
    let mut t0 = 0i64;
    let mut t1 = 1i64;
    let mut r0 = 65537i64;
    let mut r1 = a as i64;
    while r1 != 0 {
        let q = r0 / r1;
        let nr = r0 - q * r1;
        r0 = r1;
        r1 = nr;
        let nt = t0 - q * t1;
        t0 = t1;
        t1 = nt;
    }
    if t0 < 0 {
        t0 += 65537;
    }
    t0 as u16
}

fn idea_enc_subkeys(key: [u8; 16]) -> [u16; 52] {
    let mut sub = [0u16; 52];
    for i in 0..8 {
        sub[i] = u16::from_be_bytes([key[i * 2], key[i * 2 + 1]]);
    }
    for i in 8..52 {
        let base = (i - 8) & !7;
        let a = sub[base + ((i + 1) % 8)];
        let b = sub[base + ((i + 2) % 8)];
        sub[i] = (a << 9) | (b >> 7);
    }
    sub
}

fn idea_dec_subkeys(enc: &[u16; 52]) -> [u16; 52] {
    let mut dec = [0u16; 52];
    let mut p = 0usize;
    dec[48] = idea_inv(enc[p]); p += 1;
    dec[49] = (0u16).wrapping_sub(enc[p]); p += 1;
    dec[50] = (0u16).wrapping_sub(enc[p]); p += 1;
    dec[51] = idea_inv(enc[p]); p += 1;

    for r in (0..8).rev() {
        let base = r * 6;
        let t1 = enc[p]; p += 1;
        let t2 = enc[p]; p += 1;
        dec[base + 4] = t1;
        dec[base + 5] = t2;

        let k0 = idea_inv(enc[p]); p += 1;
        let k1 = (0u16).wrapping_sub(enc[p]); p += 1;
        let k2 = (0u16).wrapping_sub(enc[p]); p += 1;
        let k3 = idea_inv(enc[p]); p += 1;

        dec[base] = k0;
        if r == 0 {
            dec[base + 1] = k1;
            dec[base + 2] = k2;
        } else {
            dec[base + 1] = k2;
            dec[base + 2] = k1;
        }
        dec[base + 3] = k3;
    }
    dec
}

/// Cifra o descifra un bloque de 8 bytes con IDEA devolviendo tambien la traza de las 8.5 rondas.
pub fn idea_block_with_trace(block: [u8; 8], subkeys: &[u16; 52]) -> ([u8; 8], Vec<[String; 5]>) {
    let mut x1 = u16::from_be_bytes([block[0], block[1]]);
    let mut x2 = u16::from_be_bytes([block[2], block[3]]);
    let mut x3 = u16::from_be_bytes([block[4], block[5]]);
    let mut x4 = u16::from_be_bytes([block[6], block[7]]);
    let mut trace = Vec::with_capacity(9);

    for r in 0..8 {
        let k = &subkeys[r * 6..r * 6 + 6];
        let y1 = idea_mul(x1, k[0]);
        let y2 = x2.wrapping_add(k[1]);
        let y3 = x3.wrapping_add(k[2]);
        let y4 = idea_mul(x4, k[3]);

        let t0 = idea_mul(y1 ^ y3, k[4]);
        let t1 = idea_mul((y2 ^ y4).wrapping_add(t0), k[5]);
        let t2 = t0.wrapping_add(t1);

        x1 = y1 ^ t1;
        x4 = y4 ^ t2;
        let a = y2 ^ t2;
        let b = y3 ^ t1;
        x2 = b;
        x3 = a;

        trace.push([
            format!("Ronda {}", r + 1),
            format!("{x1:04X}"),
            format!("{x2:04X}"),
            format!("{x3:04X}"),
            format!("{x4:04X}"),
        ]);
    }

    let z1 = idea_mul(x1, subkeys[48]);
    let z2 = x3.wrapping_add(subkeys[49]);
    let z3 = x2.wrapping_add(subkeys[50]);
    let z4 = idea_mul(x4, subkeys[51]);

    trace.push([
        "Final 8.5".into(),
        format!("{z1:04X}"),
        format!("{z2:04X}"),
        format!("{z3:04X}"),
        format!("{z4:04X}"),
    ]);

    let mut out = [0u8; 8];
    out[0..2].copy_from_slice(&z1.to_be_bytes());
    out[2..4].copy_from_slice(&z2.to_be_bytes());
    out[4..6].copy_from_slice(&z3.to_be_bytes());
    out[6..8].copy_from_slice(&z4.to_be_bytes());
    (out, trace)
}

fn idea_transform_bytes(data: &[u8], subkeys: &[u16; 52]) -> (Vec<u8>, Vec<[String; 5]>) {
    let mut out = Vec::with_capacity(data.len());
    let mut first_trace = Vec::new();
    for (idx, chunk) in data.chunks_exact(8).enumerate() {
        let mut blk = [0u8; 8];
        blk.copy_from_slice(chunk);
        let (res, tr) = idea_block_with_trace(blk, subkeys);
        if idx == 0 {
            first_trace = tr;
        }
        out.extend_from_slice(&res);
    }
    (out, first_trace)
}

pub(crate) fn run_idea(action: Action, text: &str, key: &str) -> Result<CipherOutput, CipherError> {
    let key_vec = parse_key_bytes(key, 16, b"IDEA128BITSECRET");
    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&key_vec);
    let enc_sk = idea_enc_subkeys(key_arr);

    match action {
        Action::Encrypt => {
            let padded = pkcs7_pad(text.as_bytes(), 8);
            let (ct, trace) = idea_transform_bytes(&padded, &enc_sk);
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: hex_encode_upper(&ct),
                explanation: format!(
                    "IDEA (128 bits, 8.5 rondas mod 65537/65536/XOR) con clave {}.",
                    hex_encode_upper(&key_arr)
                ),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "idea_rounds".into(),
                    headers: vec!["Paso".into(), "X1".into(), "X2".into(), "X3".into(), "X4".into()],
                    rows: trace.into_iter().map(|r| r.to_vec()).collect(),
                }),
                meta: Vec::new(),
            })
        }
        Action::Decrypt | Action::Solve => {
            if text.trim().is_empty() {
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "Introduce bytes hexadecimales cifrados con IDEA para descifrar.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            let ct = hex_decode(text)?;
            let mut try_keys = vec![(
                format!("Clave '{}'", if key.trim().is_empty() { "default" } else { key.trim() }),
                key_arr,
            )];
            if action == Action::Solve {
                for kw in ["IDEA128BITSECRET", "SECRETOIDEA12345", "00010002000300040005000600070008", "CLAVE128BITSIDEA"] {
                    let kv = parse_key_bytes(kw, 16, b"IDEA128BITSECRET");
                    let mut ka = [0u8; 16];
                    ka.copy_from_slice(&kv);
                    try_keys.push((format!("Diccionario '{kw}'"), ka));
                }
            }
            let mut ranked = Vec::new();
            for (lbl, ka) in try_keys {
                let dsk = idea_dec_subkeys(&idea_enc_subkeys(ka));
                let (pt_pad, tr) = idea_transform_bytes(&ct, &dsk);
                if let Ok(pt) = pkcs7_unpad(&pt_pad, 8) {
                    let txt = bytes_to_readable(&pt);
                    ranked.push((lbl, txt.clone(), score_text(&txt), tr));
                }
            }
            if ranked.is_empty() {
                return Err(CipherError::InvalidInput("no se pudo descifrar IDEA con la clave indicada".into()));
            }
            if action == Action::Solve {
                ranked.sort_by(|a, b| b.2.total_cmp(&a.2));
            }
            let (_, best_txt, _, tr) = ranked[0].clone();
            let cands = if action == Action::Solve {
                ranked.into_iter().map(|(label, text, score, _)| Candidate { label, text, score }).collect()
            } else {
                Vec::new()
            };
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: best_txt,
                explanation: "Descifrado IDEA con inversos multiplicativos mod 65537 y aditivos mod 65536.".into(),
                candidates: cands,
                grid: Some(GridData {
                    kind: "idea_rounds".into(),
                    headers: vec!["Paso".into(), "X1".into(), "X2".into(), "X3".into(), "X4".into()],
                    rows: tr.into_iter().map(|r| r.to_vec()).collect(),
                }),
                meta: Vec::new(),
            })
        }
    }
}

// ============================================================================
// 17. AES-128 / AES-192 / AES-256 (FIPS 197)
// ============================================================================

const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

const AES_RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1B } else { 0 }
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn aes_key_expansion(key: &[u8]) -> (Vec<[u8; 16]>, usize) {
    let nk = key.len() / 4;
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);
    let mut w = vec![[0u8; 4]; total_words];
    for i in 0..nk {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = [AES_SBOX[temp[1] as usize], AES_SBOX[temp[2] as usize], AES_SBOX[temp[3] as usize], AES_SBOX[temp[0] as usize]];
            temp[0] ^= AES_RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            temp = [AES_SBOX[temp[0] as usize], AES_SBOX[temp[1] as usize], AES_SBOX[temp[2] as usize], AES_SBOX[temp[3] as usize]];
        }
        for b in 0..4 {
            w[i][b] = w[i - nk][b] ^ temp[b];
        }
    }
    let round_keys = (0..=nr)
        .map(|r| {
            let mut rk = [0u8; 16];
            for c in 0..4 {
                rk[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
            rk
        })
        .collect();
    (round_keys, nr)
}

fn aes_add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s ^= *k;
    }
}

fn aes_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
}

fn aes_inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[1] = t[13]; s[5] = t[1]; s[9] = t[5]; s[13] = t[9];
    s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
    s[3] = t[7]; s[7] = t[11]; s[11] = t[15]; s[15] = t[3];
}

fn aes_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn aes_inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[i + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[i + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[i + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// Cifra o descifra un bloque de 16 bytes con AES devolviendo los estados 4x4 por ronda.
pub fn aes_block_with_states(block: [u8; 16], key: &[u8], encrypt: bool) -> ([u8; 16], Vec<[u8; 16]>) {
    let (rks, nr) = aes_key_expansion(key);
    let mut state = block;
    let mut snapshots = Vec::with_capacity(nr + 1);

    if encrypt {
        aes_add_round_key(&mut state, &rks[0]);
        snapshots.push(state);
        for rk in rks.iter().take(nr).skip(1) {
            for b in &mut state {
                *b = AES_SBOX[*b as usize];
            }
            aes_shift_rows(&mut state);
            aes_mix_columns(&mut state);
            aes_add_round_key(&mut state, rk);
            snapshots.push(state);
        }
        for b in &mut state {
            *b = AES_SBOX[*b as usize];
        }
        aes_shift_rows(&mut state);
        aes_add_round_key(&mut state, &rks[nr]);
        snapshots.push(state);
    } else {
        aes_add_round_key(&mut state, &rks[nr]);
        snapshots.push(state);
        for r in (1..nr).rev() {
            aes_inv_shift_rows(&mut state);
            for b in &mut state {
                *b = AES_INV_SBOX[*b as usize];
            }
            aes_add_round_key(&mut state, &rks[r]);
            aes_inv_mix_columns(&mut state);
            snapshots.push(state);
        }
        aes_inv_shift_rows(&mut state);
        for b in &mut state {
            *b = AES_INV_SBOX[*b as usize];
        }
        aes_add_round_key(&mut state, &rks[0]);
        snapshots.push(state);
    }
    (state, snapshots)
}

fn aes_key_len_from_param(key: &str, param: &str) -> usize {
    let p = param.trim();
    if p == "192" {
        return 24;
    }
    if p == "256" {
        return 32;
    }
    if p == "128" {
        return 16;
    }
    let hex_cand = key.trim().strip_prefix("0x").or_else(|| key.trim().strip_prefix("0X")).unwrap_or(key.trim());
    if hex_cand.chars().all(|c| c.is_ascii_hexdigit()) {
        if hex_cand.len() == 64 {
            return 32;
        }
        if hex_cand.len() == 48 {
            return 24;
        }
    }
    16
}

fn aes_state_to_grid(state: &[u8; 16]) -> GridData {
    let rows = (0..4)
        .map(|r| (0..4).map(|c| format!("{:02X}", state[c * 4 + r])).collect())
        .collect();
    GridData {
        kind: "aes_state".into(),
        headers: vec!["Col 0".into(), "Col 1".into(), "Col 2".into(), "Col 3".into()],
        rows,
    }
}

pub(crate) fn run_aes(action: Action, text: &str, key: &str, param: &str) -> Result<CipherOutput, CipherError> {
    let key_len = aes_key_len_from_param(key, param);
    let bits = key_len * 8;
    let key_bytes = parse_key_bytes(key, key_len, &b"AES-CIPHER-STUDIO-256BIT-DEFAULT"[..key_len]);

    match action {
        Action::Encrypt => {
            let padded = pkcs7_pad(text.as_bytes(), 16);
            let mut out = Vec::with_capacity(padded.len());
            let mut snaps = Vec::new();
            for (idx, chunk) in padded.chunks_exact(16).enumerate() {
                let mut blk = [0u8; 16];
                blk.copy_from_slice(chunk);
                let (res, st) = aes_block_with_states(blk, &key_bytes, true);
                if idx == 0 {
                    snaps = st;
                }
                out.extend_from_slice(&res);
            }
            let last_state = snaps.last().copied().unwrap_or([0u8; 16]);
            let rounds_meta = snaps.iter().map(|s| hex_encode_upper(s)).collect::<Vec<_>>().join(",");
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: hex_encode_upper(&out),
                explanation: format!(
                    "AES-{bits} (FIPS 197, {} rondas, SubBytes/ShiftRows/MixColumns) con clave {}.",
                    key_len / 4 + 6,
                    hex_encode_upper(&key_bytes)
                ),
                candidates: Vec::new(),
                grid: Some(aes_state_to_grid(&last_state)),
                meta: vec![
                    MetaEntry { key: "bits".into(), value: bits.to_string() },
                    MetaEntry { key: "rounds_states".into(), value: rounds_meta },
                ],
            })
        }
        Action::Decrypt | Action::Solve => {
            if text.trim().is_empty() {
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "Introduce bytes hexadecimales cifrados con AES para descifrar.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            let ct = hex_decode(text)?;
            let mut try_keys = vec![(
                format!("AES-{bits} '{}'", if key.trim().is_empty() { "default" } else { key.trim() }),
                key_bytes,
            )];
            if action == Action::Solve {
                for kw in ["CLAVE-AES-128BIT", "SECRETO-AES-256-BITS-RUST-STUDIO", "000102030405060708090A0B0C0D0E0F", "PASSWORD12345678"] {
                    let kl = aes_key_len_from_param(kw, param);
                    let kb = parse_key_bytes(kw, kl, &b"AES-CIPHER-STUDIO-256BIT-DEFAULT"[..kl]);
                    try_keys.push((format!("Diccionario '{kw}'"), kb));
                }
            }
            let mut ranked = Vec::new();
            for (lbl, kb) in try_keys {
                let mut pt_pad = Vec::with_capacity(ct.len());
                let mut snaps = Vec::new();
                for (idx, chunk) in ct.chunks_exact(16).enumerate() {
                    let mut blk = [0u8; 16];
                    blk.copy_from_slice(chunk);
                    let (res, st) = aes_block_with_states(blk, &kb, false);
                    if idx == 0 {
                        snaps = st;
                    }
                    pt_pad.extend_from_slice(&res);
                }
                if let Ok(pt) = pkcs7_unpad(&pt_pad, 16) {
                    let txt = bytes_to_readable(&pt);
                    ranked.push((lbl, txt.clone(), score_text(&txt), snaps));
                }
            }
            if ranked.is_empty() {
                return Err(CipherError::InvalidInput("no se pudo descifrar AES (verifica clave o longitud 128/192/256)".into()));
            }
            if action == Action::Solve {
                ranked.sort_by(|a, b| b.2.total_cmp(&a.2));
            }
            let (_, best_txt, _, snaps) = ranked[0].clone();
            let last_state = snaps.last().copied().unwrap_or([0u8; 16]);
            let rounds_meta = snaps.iter().map(|s| hex_encode_upper(s)).collect::<Vec<_>>().join(",");
            let cands = if action == Action::Solve {
                ranked.into_iter().map(|(label, text, score, _)| Candidate { label, text, score }).collect()
            } else {
                Vec::new()
            };
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: best_txt,
                explanation: format!("Descifrado AES-{bits} inverso completado."),
                candidates: cands,
                grid: Some(aes_state_to_grid(&last_state)),
                meta: vec![
                    MetaEntry { key: "bits".into(), value: bits.to_string() },
                    MetaEntry { key: "rounds_states".into(), value: rounds_meta },
                ],
            })
        }
    }
}

// ============================================================================
// 18. MD5 (RFC 1321)
// ============================================================================

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Calcula el hash MD5 de 128 bits (16 bytes) y devuelve tambien los 4 registros (A,B,C,D).
pub fn md5_raw(input: &[u8]) -> ([u8; 16], [u32; 4]) {
    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let sum = a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(MD5_S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    (digest, [a0, b0, c0, d0])
}

fn md5_hex(input: &[u8]) -> (String, [u32; 4]) {
    let (d, regs) = md5_raw(input);
    (hex_encode_lower(&d), regs)
}

fn crack_md5(target_hex: &str) -> Option<String> {
    let target = target_hex.trim().to_ascii_lowercase();
    if target.len() != 32 || !target.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    for word in [
        "", "abc", "message digest", "123456", "password", "admin", "hola", "secreto",
        "clave", "rust", "ataque", "qwerty", "letmein", "test", "cipher", "madrid",
        "espana", "tesoro", "amanecer", "hola mundo", "ATAQUE AL AMANECER", "1234",
        "12345", "12345678", "0000", "root", "user", "demo", "md5", "crypto",
    ] {
        if md5_hex(word.as_bytes()).0 == target {
            return Some(word.to_owned());
        }
    }
    for pin in 0..10000u32 {
        let s = format!("{pin:04}");
        if md5_hex(s.as_bytes()).0 == target {
            return Some(s);
        }
    }
    None
}

pub(crate) fn run_md5(action: Action, text: &str) -> Result<CipherOutput, CipherError> {
    match action {
        Action::Encrypt => {
            let (digest, regs) = md5_hex(text.as_bytes());
            let mut mutated = text.as_bytes().to_vec();
            if let Some(first) = mutated.first_mut() {
                *first ^= 1;
            } else {
                mutated.push(b'!');
            }
            let (avalanche, _) = md5_hex(&mutated);
            let reg_rows = vec![
                vec!["A".into(), format!("0x{:08x}", regs[0]), digest[0..8].to_owned()],
                vec!["B".into(), format!("0x{:08x}", regs[1]), digest[8..16].to_owned()],
                vec!["C".into(), format!("0x{:08x}", regs[2]), digest[16..24].to_owned()],
                vec!["D".into(), format!("0x{:08x}", regs[3]), digest[24..32].to_owned()],
            ];
            Ok(CipherOutput {
                cipher: String::new(),
                action: String::new(),
                result: digest.clone(),
                explanation: format!(
                    "Hash MD5 (RFC 1321, 128 bits, 64 pasos). Efecto avalancha (+1 bit): {avalanche}"
                ),
                candidates: Vec::new(),
                grid: Some(GridData {
                    kind: "md5_digest".into(),
                    headers: vec!["Registro".into(), "Estado 32-bit".into(), "Bytes Digest".into()],
                    rows: reg_rows,
                }),
                meta: vec![
                    MetaEntry { key: "digest".into(), value: digest },
                    MetaEntry { key: "avalanche".into(), value: avalanche },
                ],
            })
        }
        Action::Decrypt => Ok(CipherOutput {
            cipher: String::new(),
            action: String::new(),
            result: "Hash unidireccional (no invertible)".into(),
            explanation: "MD5 es una funcion resumen criptografica unidireccional: comprime cualquier entrada en 128 bits. Usa 'Resolver / Crackear' para buscar preimagenes por diccionario y PINs 0000-9999.".into(),
            candidates: Vec::new(),
            grid: None,
            meta: Vec::new(),
        }),
        Action::Solve => {
            let trimmed = text.trim();
            if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(found) = crack_md5(trimmed) {
                    let (_, regs) = md5_hex(found.as_bytes());
                    return Ok(CipherOutput {
                        cipher: String::new(),
                        action: String::new(),
                        result: found.clone(),
                        explanation: format!("Preimagen MD5 encontrada en diccionario / fuerza bruta PIN en Rust: '{found}'."),
                        candidates: vec![Candidate {
                            label: "Coincidencia exacta MD5".into(),
                            text: found,
                            score: 100.0,
                        }],
                        grid: Some(GridData {
                            kind: "md5_digest".into(),
                            headers: vec!["Registro".into(), "Estado 32-bit".into(), "Bytes Digest".into()],
                            rows: vec![
                                vec!["A".into(), format!("0x{:08x}", regs[0]), trimmed[0..8].to_ascii_lowercase()],
                                vec!["B".into(), format!("0x{:08x}", regs[1]), trimmed[8..16].to_ascii_lowercase()],
                                vec!["C".into(), format!("0x{:08x}", regs[2]), trimmed[16..24].to_ascii_lowercase()],
                                vec!["D".into(), format!("0x{:08x}", regs[3]), trimmed[24..32].to_ascii_lowercase()],
                            ],
                        }),
                        meta: Vec::new(),
                    });
                }
                return Ok(CipherOutput {
                    cipher: String::new(),
                    action: String::new(),
                    result: String::new(),
                    explanation: "El hash MD5 no coincide con el diccionario ni con PINs 0000..9999.".into(),
                    candidates: Vec::new(),
                    grid: None,
                    meta: Vec::new(),
                });
            }
            run_md5(Action::Encrypt, text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_official_nist_vector() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let (ct, _) = des_block_with_trace(pt, key, true);
        assert_eq!(hex_encode_upper(&ct), "85E813540F0AB405");
        let (dec, _) = des_block_with_trace(ct, key, false);
        assert_eq!(dec, pt);
    }

    #[test]
    fn idea_official_test_vector() {
        let key = [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8];
        let pt = [0, 0, 0, 1, 0, 2, 0, 3];
        let enc_sk = idea_enc_subkeys(key);
        let (ct, _) = idea_block_with_trace(pt, &enc_sk);
        assert_eq!(hex_encode_upper(&ct), "11FBED2B01986DE5");
        let dec_sk = idea_dec_subkeys(&enc_sk);
        let (dec, _) = idea_block_with_trace(ct, &dec_sk);
        assert_eq!(dec, pt);
    }

    #[test]
    fn aes_official_fips197_vectors() {
        let k128 = hex_decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex_decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let mut p16 = [0u8; 16];
        p16.copy_from_slice(&pt);
        let (ct128, _) = aes_block_with_states(p16, &k128, true);
        assert_eq!(hex_encode_upper(&ct128), "69C4E0D86A7B0430D8CDB78070B4C55A");
        let (dec128, _) = aes_block_with_states(ct128, &k128, false);
        assert_eq!(dec128, p16);

        let k256 = hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
        let (ct256, _) = aes_block_with_states(p16, &k256, true);
        assert_eq!(hex_encode_upper(&ct256), "8EA2B7CA516745BFEAFC49904B496089");
        let (dec256, _) = aes_block_with_states(ct256, &k256, false);
        assert_eq!(dec256, p16);
    }

    #[test]
    fn md5_official_rfc1321_vectors() {
        assert_eq!(md5_hex(b"").0, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc").0, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"message digest").0, "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(crack_md5("e10adc3949ba59abbe56e057f20f883e").as_deref(), Some("123456"));
    }
}
