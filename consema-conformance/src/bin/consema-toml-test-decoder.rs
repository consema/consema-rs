//! `toml-test` tagged-JSON decoder adapter over Consema public TOML APIs.

use consema_document::ParseLimits;
use consema_toml::{TomlDateTime, TomlItem, TomlItemKind, TomlOffset, TomlProfile, parse};
use std::fmt::Write as _;
use std::io::Read as _;

fn main() {
    let mut source = Vec::new();
    if let Err(error) = std::io::stdin().read_to_end(&mut source) {
        eprintln!("stdin: {error}");
        std::process::exit(1);
    }
    let document = match parse(source, TomlProfile::Toml10V1, ParseLimits::default()) {
        Ok(document) => document,
        Err(failure) => {
            for diagnostic in failure.diagnostics() {
                eprintln!("{}", diagnostic.code);
            }
            std::process::exit(1);
        }
    };
    let mut output = String::new();
    write_item(document.root(), &mut output);
    println!("{output}");
}

fn write_item(item: TomlItem<'_>, output: &mut String) {
    match item.kind() {
        TomlItemKind::RootTable
        | TomlItemKind::StandardTable
        | TomlItemKind::ImplicitTable
        | TomlItemKind::DottedTable
        | TomlItemKind::InlineTable => write_table(item, output),
        TomlItemKind::Array | TomlItemKind::ArrayOfTables => write_array(item, output),
        TomlItemKind::String => {
            write_tagged("string", item.as_string().expect("typed string"), output);
        }
        TomlItemKind::Integer => {
            write_tagged(
                "integer",
                &item.as_integer().expect("typed integer").to_string(),
                output,
            );
        }
        TomlItemKind::Float => {
            let value = f64::from_bits(item.as_float().expect("typed float").bits());
            write_tagged("float", &value.to_string(), output);
        }
        TomlItemKind::Boolean => {
            write_tagged(
                "bool",
                &item.as_boolean().expect("typed boolean").to_string(),
                output,
            );
        }
        TomlItemKind::OffsetDateTime => write_tagged(
            "datetime",
            &format_datetime(item.as_date_time().expect("typed datetime")),
            output,
        ),
        TomlItemKind::LocalDateTime => write_tagged(
            "datetime-local",
            &format_datetime(item.as_date_time().expect("typed datetime")),
            output,
        ),
        TomlItemKind::LocalDate => write_tagged(
            "date-local",
            &format_datetime(item.as_date_time().expect("typed date")),
            output,
        ),
        TomlItemKind::LocalTime => write_tagged(
            "time-local",
            &format_datetime(item.as_date_time().expect("typed time")),
            output,
        ),
    }
}

fn write_table(item: TomlItem<'_>, output: &mut String) {
    output.push('{');
    for (ordinal, entry) in item
        .table_entries()
        .expect("typed table")
        .into_iter()
        .enumerate()
    {
        if ordinal != 0 {
            output.push(',');
        }
        write_json_string(entry.name(), output);
        output.push(':');
        write_item(entry.item(), output);
    }
    output.push('}');
}

fn write_array(item: TomlItem<'_>, output: &mut String) {
    output.push('[');
    for (ordinal, element) in item
        .array_elements()
        .expect("typed array")
        .into_iter()
        .enumerate()
    {
        if ordinal != 0 {
            output.push(',');
        }
        write_item(element.item(), output);
    }
    output.push(']');
}

fn write_tagged(kind: &str, value: &str, output: &mut String) {
    output.push_str("{\"type\":");
    write_json_string(kind, output);
    output.push_str(",\"value\":");
    write_json_string(value, output);
    output.push('}');
}

fn write_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("write to String is infallible");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn format_datetime(value: &TomlDateTime) -> String {
    let mut output = String::new();
    if let Some(date) = value.date {
        write!(output, "{:04}-{:02}-{:02}", date.year, date.month, date.day)
            .expect("write to String is infallible");
    }
    if let Some(time) = value.time {
        if value.date.is_some() {
            output.push('T');
        }
        write!(
            output,
            "{:02}:{:02}:{:02}",
            time.hour, time.minute, time.second
        )
        .expect("write to String is infallible");
        if time.nanosecond != 0 {
            let mut fraction = format!("{:09}", time.nanosecond);
            while fraction.ends_with('0') {
                fraction.pop();
            }
            output.push('.');
            output.push_str(&fraction);
        }
    }
    if let Some(offset) = value.offset {
        match offset {
            TomlOffset::Z => output.push('Z'),
            TomlOffset::CustomMinutes(minutes) => {
                let sign = if minutes < 0 { '-' } else { '+' };
                let magnitude = minutes.unsigned_abs();
                write!(output, "{sign}{:02}:{:02}", magnitude / 60, magnitude % 60)
                    .expect("write to String is infallible");
            }
        }
    }
    output
}
