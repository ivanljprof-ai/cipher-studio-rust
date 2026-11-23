//! Servidor HTTP nativo multihilo sin dependencias externas para la suite de cifrados.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use cifrados_rust::{
    execute, json_escape, output_to_json, parse_cipher_request_json, presets_json, project_info_json,
};

const EMBEDDED_INDEX_HTML: &str = include_str!("../static/index.html");

fn load_index_html() -> String {
    fs::read_to_string("static/index.html").unwrap_or_else(|_| EMBEDDED_INDEX_HTML.to_owned())
}

fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8484".to_owned());
    let addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("Error al enlazar {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("Suite Criptografica Rust activa en http://{addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                thread::spawn(|| {
                    if let Err(err) = handle_connection(conn) {
                        eprintln!("Error procesando peticion: {err}");
                    }
                });
            }
            Err(err) => eprintln!("Error aceptando conexion: {err}"),
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        let read = reader.read_line(&mut header)?;
        if read == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, val)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
            && let Ok(len) = val.trim().parse::<usize>()
        {
            content_length = len.min(1_048_576);
        }
    }

    let mut body_buf = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_buf)?;
    }

    match (method, path) {
        ("OPTIONS", _) => write_response(&mut stream, "204 No Content", "text/plain; charset=utf-8", ""),
        ("GET", "/") | ("GET", "/index.html") => {
            let html = load_index_html();
            write_response(&mut stream, "200 OK", "text/html; charset=utf-8", &html)
        }
        ("GET", "/api/presets") => {
            let payload = presets_json();
            write_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload)
        }
        ("GET", "/api/info") => {
            let payload = project_info_json();
            write_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload)
        }
        ("POST", "/api/cipher") => {
            let body = String::from_utf8_lossy(&body_buf);
            match parse_cipher_request_json(&body).and_then(|req| execute(&req)) {
                Ok(out) => {
                    let json = output_to_json(&out);
                    write_response(&mut stream, "200 OK", "application/json; charset=utf-8", &json)
                }
                Err(err) => {
                    let msg = format!("{{\"error\":\"{}\"}}", json_escape(&err.to_string()));
                    write_response(&mut stream, "400 Bad Request", "application/json; charset=utf-8", &msg)
                }
            }
        }
        _ => write_response(
            &mut stream,
            "404 Not Found",
            "application/json; charset=utf-8",
            "{\"error\":\"ruta no encontrada\"}",
        ),
    }
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}
