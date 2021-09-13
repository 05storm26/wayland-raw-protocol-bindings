#![recursion_limit = "128"]
#![allow(dead_code, non_camel_case_types, unused_unsafe, unused_variables)]
#![allow(non_upper_case_globals, non_snake_case, unused_imports)]
#![allow(deprecated, missing_docs)]

extern crate proc_macro2;
#[macro_use]
extern crate quote;
extern crate xml;

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use xml::attribute::OwnedAttribute;
use xml::reader::ParserConfig;
use xml::reader::XmlEvent;
use xml::EventReader;

use std::env::var;

use std::iter;

use proc_macro2::{Ident, Literal, Span, TokenStream};

use std::cmp;
use std::iter::repeat;

use std::ascii::AsciiExt;

use quote::ToTokens;

#[derive(Clone, Debug)]
pub struct Protocol {
    pub name: String,
    pub copyright: Option<String>,
    pub description: Option<(String, String)>,
    pub interfaces: Vec<Interface>,
}

impl Protocol {
    pub fn new(name: String) -> Protocol {
        Protocol {
            name,
            copyright: None,
            description: None,
            interfaces: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub version: u32,
    pub description: Option<(String, String)>,
    pub requests: Vec<Message>,
    pub events: Vec<Message>,
    pub enums: Vec<Enum>,
}

impl Interface {
    pub fn new() -> Interface {
        Interface {
            name: String::new(),
            version: 1,
            description: None,
            requests: Vec::new(),
            events: Vec::new(),
            enums: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Message {
    pub name: String,
    pub typ: Option<Type>,
    pub since: u32,
    pub description: Option<(String, String)>,
    pub args: Vec<Arg>,
    pub type_index: usize,
}

impl Message {
    pub fn new() -> Message {
        Message {
            name: String::new(),
            typ: None,
            since: 1,
            description: None,
            args: Vec::new(),
            type_index: 0,
        }
    }

    pub fn all_null(&self) -> bool {
        self.args
            .iter()
            .all(|a| !((a.typ == Type::Object || a.typ == Type::NewId) && a.interface.is_some()))
    }
}

#[derive(Clone, Debug)]
pub struct Arg {
    pub name: String,
    pub typ: Type,
    pub interface: Option<String>,
    pub summary: Option<String>,
    pub description: Option<(String, String)>,
    pub allow_null: bool,
    pub enum_: Option<String>,
}

impl Arg {
    pub fn new() -> Arg {
        Arg {
            name: String::new(),
            typ: Type::Object,
            interface: None,
            summary: None,
            description: None,
            allow_null: false,
            enum_: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Enum {
    pub name: String,
    pub since: u16,
    pub description: Option<(String, String)>,
    pub entries: Vec<Entry>,
    pub bitfield: bool,
}

impl Enum {
    pub fn new() -> Enum {
        Enum {
            name: String::new(),
            since: 1,
            description: None,
            entries: Vec::new(),
            bitfield: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub value: u32,
    pub since: u16,
    pub description: Option<(String, String)>,
    pub summary: Option<String>,
}

impl Entry {
    pub fn new() -> Entry {
        Entry {
            name: String::new(),
            value: 0,
            since: 1,
            description: None,
            summary: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Type {
    Int,
    Uint,
    Fixed,
    String,
    Object,
    NewId,
    Array,
    Fd,
    Destructor,
}

impl Type {
    pub fn nullable(self) -> bool {
        match self {
            Type::String | Type::Object | Type::NewId | Type::Array => true,
            _ => false,
        }
    }

    pub fn rust_type(self) -> TokenStream {
        match self {
            Type::Int => quote!(i32),
            Type::Uint => quote!(u32),
            Type::Fixed => quote!(wl_fixed_t),
            Type::Array => quote!(*mut wl_array),
            Type::Fd => quote!(::std::os::unix::io::RawFd),
            Type::String => quote!(*mut c_char),
            Type::Object => quote!(*mut wl_proxy),
            _ => quote!(()),
        }
    }

    pub fn common_type(self) -> TokenStream {
        match self {
            Type::Int => quote!(Int),
            Type::Uint => quote!(Uint),
            Type::Fixed => quote!(Fixed),
            Type::Array => quote!(Array),
            Type::Fd => quote!(Fd),
            Type::String => quote!(Str),
            Type::Object => quote!(Object),
            Type::NewId => quote!(NewId),
            Type::Destructor => panic!("Destructor is not a valid argument type."),
        }
    }
}

macro_rules! extract_from(
    ($it: expr => $pattern: pat => $result: expr) => (
        match $it.next() {
            Ok($pattern) => { $result },
            e => panic!("Ill-formed protocol file: {:?}", e)
        }
    )
);

macro_rules! extract_end_tag(
    ($it: expr => $tag: expr) => (
        extract_from!($it => XmlEvent::EndElement { name } => {
            assert!(name.local_name == $tag, "Ill-formed protocol file");
        });
    )
);

pub fn parse_stream<S: Read>(stream: S) -> Protocol {
    let mut reader =
        EventReader::new_with_config(stream, ParserConfig::new().trim_whitespace(true));
    reader.next().expect("Could not read from event reader");
    parse_protocol(reader)
}

fn parse_protocol<R: Read>(mut reader: EventReader<R>) -> Protocol {
    let mut protocol = extract_from!(
        reader => XmlEvent::StartElement { name, attributes, .. } => {
            assert!(name.local_name == "protocol", "Missing protocol toplevel tag");
            assert!(attributes[0].name.local_name == "name", "Protocol must have a name");
            Protocol::new(attributes[0].value.clone())
        }
    );

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => {
                match &name.local_name[..] {
                    "copyright" => {
                        // parse the copyright
                        let copyright = match reader.next() {
                            Ok(XmlEvent::Characters(copyright))
                            | Ok(XmlEvent::CData(copyright)) => copyright,
                            e => panic!("Ill-formed protocol file: {:?}", e),
                        };

                        extract_end_tag!(reader => "copyright");
                        protocol.copyright = Some(copyright);
                    }
                    "interface" => {
                        protocol
                            .interfaces
                            .push(parse_interface(&mut reader, attributes));
                    }
                    "description" => {
                        protocol.description = Some(parse_description(&mut reader, attributes));
                    }
                    _ => panic!(
                        "Ill-formed protocol file: unexpected token `{}` in protocol {}",
                        name.local_name, protocol.name
                    ),
                }
            }
            Ok(XmlEvent::EndElement { name }) => {
                assert!(
                    name.local_name == "protocol",
                    "Unexpected closing token `{}`",
                    name.local_name
                );
                break;
            }
            e => panic!("Ill-formed protocol file: {:?}", e),
        }
    }

    protocol
}

fn parse_interface<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Interface {
    let mut interface = Interface::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => interface.name = attr.value,
            "version" => interface.version = attr.value.parse().unwrap(),
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => {
                    interface.description = Some(parse_description(reader, attributes))
                }
                "request" => interface.requests.push(parse_request(reader, attributes)),
                "event" => interface.events.push(parse_event(reader, attributes)),
                "enum" => interface.enums.push(parse_enum(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "interface" => break,
            _ => {}
        }
    }

    interface
}

fn parse_description<R: Read>(
    reader: &mut EventReader<R>,
    attrs: Vec<OwnedAttribute>,
) -> (String, String) {
    let mut summary = String::new();
    for attr in attrs {
        if &attr.name.local_name[..] == "summary" {
            summary = attr.value.split_whitespace().collect::<Vec<_>>().join(" ");
        }
    }

    let description = match reader.next() {
        Ok(XmlEvent::Characters(txt)) => {
            extract_end_tag!(reader => "description");
            txt
        }
        Ok(XmlEvent::EndElement { ref name }) if name.local_name == "description" => String::new(),
        e => panic!("Ill-formed protocol file: {:?}", e),
    };

    (summary, description)
}

fn parse_request<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Message {
    let mut request = Message::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => request.name = attr.value,
            "type" => request.typ = Some(parse_type(&attr.value)),
            "since" => request.since = attr.value.parse().unwrap(),
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => request.description = Some(parse_description(reader, attributes)),
                "arg" => request.args.push(parse_arg(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "request" => break,
            _ => {}
        }
    }

    request
}

fn parse_enum<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Enum {
    let mut enu = Enum::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => enu.name = attr.value,
            "since" => enu.since = attr.value.parse().unwrap(),
            "bitfield" => {
                if &attr.value[..] == "true" {
                    enu.bitfield = true
                }
            }
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => enu.description = Some(parse_description(reader, attributes)),
                "entry" => enu.entries.push(parse_entry(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "enum" => break,
            _ => {}
        }
    }

    enu
}

fn parse_event<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Message {
    let mut event = Message::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => event.name = attr.value,
            "since" => event.since = attr.value.parse().unwrap(),
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => event.description = Some(parse_description(reader, attributes)),
                "arg" => event.args.push(parse_arg(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "event" => break,
            _ => {}
        }
    }

    event
}

fn parse_arg<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Arg {
    let mut arg = Arg::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => arg.name = attr.value,
            "type" => arg.typ = parse_type(&attr.value),
            "summary" => {
                arg.summary = Some(attr.value.split_whitespace().collect::<Vec<_>>().join(" "))
            }
            "interface" => arg.interface = Some(attr.value),
            "allow-null" => {
                if attr.value == "true" {
                    arg.allow_null = true
                }
            }
            "enum" => arg.enum_ = Some(attr.value),
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => arg.description = Some(parse_description(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "arg" => break,
            _ => {}
        }
    }

    arg
}

fn parse_type(txt: &str) -> Type {
    match txt {
        "int" => Type::Int,
        "uint" => Type::Uint,
        "fixed" => Type::Fixed,
        "string" => Type::String,
        "object" => Type::Object,
        "new_id" => Type::NewId,
        "array" => Type::Array,
        "fd" => Type::Fd,
        "destructor" => Type::Destructor,
        e => panic!("Unexpected type: {}", e),
    }
}

fn parse_entry<R: Read>(reader: &mut EventReader<R>, attrs: Vec<OwnedAttribute>) -> Entry {
    let mut entry = Entry::new();
    for attr in attrs {
        match &attr.name.local_name[..] {
            "name" => entry.name = attr.value,
            "value" => {
                entry.value = if attr.value.starts_with("0x") {
                    u32::from_str_radix(&attr.value[2..], 16).unwrap()
                } else {
                    attr.value.parse().unwrap()
                };
            }
            "since" => entry.since = attr.value.parse().unwrap(),
            "summary" => {
                entry.summary = Some(attr.value.split_whitespace().collect::<Vec<_>>().join(" "))
            }
            _ => {}
        }
    }

    loop {
        match reader.next() {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => match &name.local_name[..] {
                "description" => entry.description = Some(parse_description(reader, attributes)),
                _ => panic!("Unexpected tocken: `{}`", name.local_name),
            },
            Ok(XmlEvent::EndElement { ref name }) if name.local_name == "entry" => break,
            _ => {}
        }
    }

    entry
}

fn load_xml<P: AsRef<Path>>(prot: P) -> Protocol {
    let pfile = File::open(prot.as_ref()).unwrap_or_else(|_| {
        panic!(
            "Unable to open protocol file `{}`.",
            prot.as_ref().display()
        )
    });
    parse_stream(pfile)
}

pub(crate) fn to_doc_attr(text: &str) -> TokenStream {
    let text = text.lines().map(str::trim).collect::<Vec<_>>().join("\n");
    let text = text.trim();

    quote!(#[doc = #text])
}

pub(crate) fn description_to_doc_attr(&(ref short, ref long): &(String, String)) -> TokenStream {
    to_doc_attr(&format!("{}\n\n{}", short, long))
}

pub fn null_terminated_byte_string_literal(string: &str) -> Literal {
    let mut val = Vec::with_capacity(string.len() + 1);
    val.extend_from_slice(string.as_bytes());
    val.push(0);

    Literal::byte_string(&val)
}

pub(crate) fn generate_interfaces_prefix<'a, T: Iterator<Item = &'a Protocol>>(
    protocols: T,
) -> TokenStream {
    let longest_nulls = protocols
        .map(|protocol| {
            protocol.interfaces.iter().fold(0, |max, interface| {
                let request_longest_null = interface.requests.iter().fold(0, |max, request| {
                    if request.all_null() {
                        cmp::max(request.args.len(), max)
                    } else {
                        max
                    }
                });
                let events_longest_null = interface.events.iter().fold(0, |max, event| {
                    if event.all_null() {
                        cmp::max(event.args.len(), max)
                    } else {
                        max
                    }
                });
                cmp::max(max, cmp::max(request_longest_null, events_longest_null))
            })
        })
        .max()
        .unwrap_or(1);

    let types_null_len = Literal::usize_unsuffixed(longest_nulls);

    let nulls = repeat(quote!(NULLPTR as *const sys::common::wl_interface)).take(longest_nulls);

    quote! {
        use std::os::raw::{c_char, c_void};

        const NULLPTR: *const c_void = 0 as *const c_void;
        static mut types_null: [*const sys::common::wl_interface; #types_null_len] = [
            #(#nulls,)*
        ];
    }
}

pub(crate) fn generate_interface(interface: &Interface) -> TokenStream {
    let requests = gen_messages(interface, &interface.requests, "requests");
    let events = gen_messages(interface, &interface.events, "events");

    let interface_ident = Ident::new(&format!("{}_interface", interface.name), Span::call_site());
    let name_value = null_terminated_byte_string_literal(&interface.name);
    let version_value = Literal::i32_unsuffixed(interface.version as i32);
    let request_count_value = Literal::i32_unsuffixed(interface.requests.len() as i32);
    let requests_value = if interface.requests.is_empty() {
        quote!(NULLPTR as *const wl_message)
    } else {
        let requests_ident = Ident::new(&format!("{}_requests", interface.name), Span::call_site());
        quote!(unsafe { &#requests_ident as *const _ })
    };
    let event_count_value = Literal::i32_unsuffixed(interface.events.len() as i32);
    let events_value = if interface.events.is_empty() {
        quote!(NULLPTR as *const wl_message)
    } else {
        let events_ident = Ident::new(&format!("{}_events", interface.name), Span::call_site());
        quote!(unsafe { &#events_ident as *const _ })
    };

    quote!(
        #requests
        #events

        /// C representation of this interface, for interop
        pub static mut #interface_ident: wl_interface = wl_interface {
            name: #name_value as *const u8 as *const c_char,
            version: #version_value,
            request_count: #request_count_value,
            requests: #requests_value,
            event_count: #event_count_value,
            events: #events_value,
        };
    )
}

fn gen_messages(interface: &Interface, messages: &[Message], which: &str) -> TokenStream {
    if messages.is_empty() {
        return TokenStream::new();
    }

    let types_arrays = messages.iter().filter_map(|msg| {
        if msg.all_null() {
            None
        } else {
            let array_ident = Ident::new(
                &format!("{}_{}_{}_types", interface.name, which, msg.name),
                Span::call_site(),
            );
            let array_len = Literal::usize_unsuffixed(msg.args.len());
            let array_values = msg.args.iter().map(|arg| match (arg.typ, &arg.interface) {
                (Type::Object, &Some(ref inter)) | (Type::NewId, &Some(ref inter)) => {
                    let module = Ident::new(inter, Span::call_site());
                    let interface_ident =
                        Ident::new(&format!("{}_interface", inter), Span::call_site());
                    quote!(unsafe { &super::#module::#interface_ident as *const wl_interface })
                }
                _ => quote!(NULLPTR as *const wl_interface),
            });

            Some(quote! {
                static mut #array_ident: [*const wl_interface; #array_len] = [
                    #(#array_values,)*
                ];
            })
        }
    });

    let message_array_ident =
        Ident::new(&format!("{}_{}", interface.name, which), Span::call_site());
    let message_array_len = Literal::usize_unsuffixed(messages.len());
    let message_array_values = messages.iter().map(|msg| {
        let name_value = null_terminated_byte_string_literal(&msg.name);
        let signature_value = Literal::byte_string(&message_signature(msg));

        let types_ident = if msg.all_null() {
            Ident::new("types_null", Span::call_site())
        } else {
            Ident::new(
                &format!("{}_{}_{}_types", interface.name, which, msg.name),
                Span::call_site(),
            )
        };

        quote! {
            wl_message {
                name: #name_value as *const u8 as *const c_char,
                signature: #signature_value as *const u8 as *const c_char,
                types: unsafe { &#types_ident as *const _ },
            }
        }
    });

    quote! {
        #(#types_arrays)*

        /// C-representation of the messages of this interface, for interop
        pub static mut #message_array_ident: [wl_message; #message_array_len] = [
            #(#message_array_values,)*
        ];
    }
}

fn message_signature(msg: &Message) -> Vec<u8> {
    let mut res = Vec::new();

    if msg.since > 1 {
        res.extend_from_slice(msg.since.to_string().as_bytes());
    }

    for arg in &msg.args {
        if arg.typ.nullable() && arg.allow_null {
            res.push(b'?');
        }
        match arg.typ {
            Type::NewId => {
                if arg.interface.is_none() {
                    res.extend_from_slice(b"su");
                }
                res.push(b'n');
            }
            Type::Uint => res.push(b'u'),
            Type::Fixed => res.push(b'f'),
            Type::String => res.push(b's'),
            Type::Object => res.push(b'o'),
            Type::Array => res.push(b'a'),
            Type::Fd => res.push(b'h'),
            Type::Int => res.push(b'i'),
            _ => {}
        }
    }

    res.push(0);
    res
}

pub fn is_keyword(txt: &str) -> bool {
    match txt {
        "abstract" | "alignof" | "as" | "become" | "box" | "break" | "const" | "continue"
        | "crate" | "do" | "else" | "enum" | "extern" | "false" | "final" | "fn" | "for" | "if"
        | "impl" | "in" | "let" | "loop" | "macro" | "match" | "mod" | "move" | "mut"
        | "offsetof" | "override" | "priv" | "proc" | "pub" | "pure" | "ref" | "return"
        | "Self" | "self" | "sizeof" | "static" | "struct" | "super" | "trait" | "true"
        | "type" | "typeof" | "unsafe" | "unsized" | "use" | "virtual" | "where" | "while"
        | "yield" | "__handler" | "__object" => true,
        _ => false,
    }
}

fn fix_ident(input: &str) -> String {
    if is_keyword(input) {
        format!("_{}", input)
    } else {
        input.to_owned()
    }
}

impl ToTokens for Enum {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let enum_decl;
        let enum_impl;

        let doc_attr = self.description.as_ref().map(description_to_doc_attr);
        let ident = Ident::new(&fix_ident(&self.name), Span::call_site());

        if self.bitfield {
            let entries = self.entries.iter().map(|entry| {
                let doc_attr = entry
                    .description
                    .as_ref()
                    .map(description_to_doc_attr)
                    .or_else(|| entry.summary.as_ref().map(|s| to_doc_attr(s)));

                let prefix = if entry.name.chars().next().unwrap().is_numeric() {
                    "_"
                } else {
                    ""
                };
                let ident = Ident::new(
                    &fix_ident(&format!("{}{}", prefix, entry.name)),
                    Span::call_site(),
                );

                let value = Literal::u32_unsuffixed(entry.value);

                quote! {
                    #doc_attr
                    const #ident = #value;
                }
            });

            enum_decl = quote! {
                bitflags! {
                    #doc_attr
                    pub struct #ident: u32 {
                        #(#entries)*
                    }
                }
            };
            enum_impl = quote! {
                impl #ident {
                    pub fn from_raw(n: u32) -> Option<#ident> {
                        Some(#ident::from_bits_truncate(n))
                    }

                    pub fn to_raw(&self) -> u32 {
                        self.bits()
                    }
                }
            };
        } else {
            let variants = self.entries.iter().map(|entry| {
                let doc_attr = entry
                    .description
                    .as_ref()
                    .map(description_to_doc_attr)
                    .or_else(|| entry.summary.as_ref().map(|s| to_doc_attr(s)));

                let prefix = if entry.name.chars().next().unwrap().is_numeric() {
                    "_"
                } else {
                    ""
                };
                let variant = Ident::new(
                    &fix_ident(&format!("{}{}", prefix, entry.name)),
                    Span::call_site(),
                );

                let value = Literal::u32_unsuffixed(entry.value);

                quote! {
                    #doc_attr
                    #variant = #value
                }
            });

            enum_decl = quote! {
                #doc_attr
                #[repr(u32)]
                #[derive(Copy, Clone, Debug, PartialEq)]
                pub enum #ident {
                    #(#variants,)*
                    #[doc(hidden)]
                    __nonexhaustive,
                }
            };

            let match_arms = self.entries.iter().map(|entry| {
                let value = Literal::u32_unsuffixed(entry.value);

                let prefix = if entry.name.chars().next().unwrap().is_numeric() {
                    "_"
                } else {
                    ""
                };
                let variant = Ident::new(
                    &fix_ident(&format!("{}{}", prefix, entry.name)),
                    Span::call_site(),
                );

                quote! {
                    #value => Some(#ident::#variant)
                }
            });

            enum_impl = quote! {
                impl #ident {
                    pub fn from_raw(n: u32) -> Option<#ident> {
                        match n {
                            #(#match_arms,)*
                            _ => Option::None
                        }
                    }

                    pub fn to_raw(&self) -> u32 {
                        *self as u32
                    }
                }
            };
        }

        enum_decl.to_tokens(tokens);
        enum_impl.to_tokens(tokens);
    }
}

pub fn dotted_to_relname(input: &str) -> TokenStream {
    let mut it = input.split('.');
    match (it.next(), it.next()) {
        (Some(module), Some(name)) => {
            let module = Ident::new(module, Span::call_site());
            let ident = Ident::new(&fix_ident(name), Span::call_site());
            quote!(super::#module::#ident)
        }
        (Some(name), None) => Ident::new(&fix_ident(name), Span::call_site()).into_token_stream(),
        _ => unreachable!(),
    }
}

fn event_method_prototype(name: &Ident, msg: &Message, side: Side) -> TokenStream {
    let method_name = Ident::new(
        &format!(
            "{}{}",
            if is_keyword(&msg.name) { "_" } else { "" },
            msg.name
        ),
        Span::call_site(),
    );

    let method_args = msg.args.iter().map(|arg| {
        let arg_name = Ident::new(
            &format!(
                "{}{}",
                if is_keyword(&arg.name) || arg.name == "object" {
                    "_"
                } else {
                    ""
                },
                arg.name
            ),
            Span::call_site(),
        );

        let arg_type_inner = if let Some(ref enu) = arg.enum_ {
            dotted_to_relname(enu)
        } else {
            match arg.typ {
                Type::Uint => quote!(u32),
                Type::Int => quote!(i32),
                Type::Fixed => quote!(wl_fixed_t),
                Type::String => quote!(*mut c_char),
                Type::Array => quote!(*mut wl_array),
                Type::Fd => quote!(::std::os::unix::io::RawFd),
                Type::Object => {
                    if let Some(ref iface) = arg.interface {
                        let iface_mod = Ident::new(&iface, Span::call_site());
                        let iface_type = Ident::new(&iface, Span::call_site());
                        quote!(*mut super::#iface_mod::#iface_type)
                    } else {
                        quote!(*mut wl_proxy)
                    }
                }
                Type::NewId => {
                    if let Some(ref iface) = arg.interface {
                        let iface_mod = Ident::new(&iface, Span::call_site());
                        let iface_type = Ident::new(&iface, Span::call_site());
                        quote!(*mut super::#iface_mod::#iface_type)
                    } else {
                        // bind-like function
                        quote!((String, u32, *mut wl_proxy))
                    }
                }
                Type::Destructor => panic!("An argument cannot have type \"destructor\"."),
            }
        };

        let field_type = if arg.allow_null {
            quote!(Option<#arg_type_inner>)
        } else {
            arg_type_inner.into_token_stream()
        };

        quote! {
            #arg_name: #field_type
        }
    });

    quote! {
        fn #method_name(&mut self, object: *mut #name, #(#method_args),*) {}
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Side {
    /// wayland client applications
    Client,
    /// wayland compositors
    Server,
}

pub(crate) fn gen_event_handler_trait(
    iname: &Ident,
    messages: &[Message],
    side: Side,
) -> TokenStream {
    let methods = messages.iter().map(|msg| {
        let mut docs = String::new();
        if let Some((ref short, ref long)) = msg.description {
            docs += &format!("{}\n\n{}\n", short, long);
        }
        if let Some(Type::Destructor) = msg.typ {
            docs += "\nThis is a destructor, you cannot send requests to this object any longer once this method is called.";
        }
        if msg.since > 1 {
            docs += &format!("\nOnly available since version {} of the interface.", msg.since);
        }

        let doc_attr = to_doc_attr(&docs);
        let proto = event_method_prototype(iname, &msg, side);

        quote! {
            #doc_attr
            #proto
        }
    });

    let method_name = Ident::new(
        &format!(
            "{}_{}",
            iname,
            if side == Side::Server {
                "interface"
            } else {
                "listener"
            }
        ),
        Span::call_site(),
    );
    match side {
        Side::Client => quote! {
            /// An interface for handling events.
            pub trait #method_name {
                #(#methods)*
            }
        },
        Side::Server => quote! {
            /// An interface for handling requests.
            pub trait #method_name {
                #(#methods)*
            }
        },
    }
}

fn generate_stubs(interface: &Interface, side: Side) -> TokenStream {
    let list = if side == Side::Client {
        &interface.requests
    } else {
        &interface.events
    };

    let sud = Ident::new(
        &format!("{}_set_user_data", interface.name),
        Span::call_site(),
    );
    let gud = Ident::new(
        &format!("{}_get_user_data", interface.name),
        Span::call_site(),
    );
    let gv = Ident::new(
        &format!("{}_get_version", interface.name),
        Span::call_site(),
    );
    
    let al = Ident::new(
        &format!("{}_add_listener", interface.name),
        Span::call_site(),
    );

    let arl = Ident::new(
        &format!("{}_add_rust_listener", interface.name),
        Span::call_site(),
    );

     let lt = Ident::new(
        &format!("{}_listener", interface.name),
        Span::call_site(),
    );


    let mut opcode = 0u32;
    let mut has_destroy = false;
    let interface_ident = Ident::new(&fix_ident(&interface.name), Span::call_site());
    let thisparam = quote!(#interface_ident: *mut super::#interface_ident::#interface_ident);


    let add_l_stub = if side == Side::Client {
        quote! {
            pub unsafe fn #al(#thisparam, listener: *mut c_void, data: *mut c_void) -> c_int {
                return ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_add_listener,
                            #interface_ident as _, listener as _, data as _);
            }

            pub unsafe fn #arl(#thisparam, listener: & dyn #lt) -> bool {
                let to = (listener as *const dyn #lt).to_raw_parts();
                let op = to.0;
                let fp = std::mem::transmute::<_, *mut c_void>(std::mem::transmute::<_, usize>(to.1) + (3 * std::mem::size_of::<usize>()) );
                return #al(#interface_ident as _, fp as _, op as _) == 0;
            }
        }
    } else {
        quote!()
    };

    let stubs = list.iter().map(|msg| {
        let result = match side {
        Side::Client => {
            let doc = msg.description.as_ref().map(description_to_doc_attr);
            let name = Ident::new(&format!("{}_{}", interface.name, msg.name), Span::call_site());

            let mut returnType = None;
            let mut returnNewType = false;

            let argsv = msg.args.iter().map(|arg| {
                let mut bindlike = false;
                let ty = match arg.typ {
                    Type::Uint => quote!(u32),
                    Type::Int => quote!(i32),
                    Type::Fixed => quote!(wl_fixed_t),
                    Type::String => quote!(*const c_char),
                    Type::Array => quote!(*mut wl_array),
                    Type::Fd => quote!(::std::os::unix::io::RawFd),
                    Type::Object => {
                        if let Some(ref iface) = arg.interface {
                            let iface_mod = Ident::new(&iface, Span::call_site());
                            let iface_type = Ident::new(&iface, Span::call_site());
                            quote!(*mut super::#iface_mod::#iface_type)
                        } else {
                            quote!(*mut wl_proxy)
                        }
                    }
                    Type::NewId => {
                        if let Some(ref iface) = arg.interface {
                            returnType = Some(iface);
                            quote!()
                        } else {
                            // bind-like function
                            returnNewType = true;
                            bindlike = true;
                            quote!(*mut wl_interface, version: u32)
                        }
                    }
                    Type::Destructor => panic!("An argument cannot have type \"destructor\"."),
                };

                let an = Ident::new(&if bindlike { "interface".to_owned() } else { fix_ident(&arg.name) }, Span::call_site());
                if !ty.is_empty() {
                    Some((an, ty, bindlike))
                } else { None }
            }).collect::<Vec<_>>();

            let paramlist = argsv.iter().filter(|o| {o.is_some()}).map(|o|{o.as_ref().unwrap().clone()}).map(|pair| {let n = &pair.0; let t = &pair.1; quote!(#n: #t)});
            let param_name_list = argsv.iter()
            .map(|o|
            {
                if let Some(pair) = o {
                    if !pair.2 {
                        let n = &pair.0;
                        quote!(#n)
                    } else {
                        quote!( (*interface).name, version, std::ptr::null::<c_void>() )
                    }
                } else {
                    quote!(std::ptr::null::<c_void>() )
                }
            });

            let args = std::iter::once(thisparam.clone())
                .chain(paramlist);

            if msg.name == "destroy" {
                has_destroy = true;
            }

            let destroy_end = if msg.typ == Some(Type::Destructor) {
                    quote!(ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_destroy,
                            #interface_ident as _);)
                } else {quote!()};

            let func = if returnNewType {
                quote! {
                    pub unsafe fn #name(#(#args),*) -> *mut wl_proxy {
                        let r = ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_marshal_constructor_versioned,
                            #interface_ident as _, #opcode, interface as _, version #(,#param_name_list)* );

                        #destroy_end

                        return r as _;
                    }
                }
            } else if let Some(iface) = returnType {
                let iface_mod = Ident::new(&fix_ident(&iface), Span::call_site());
                let iface_type = Ident::new(&fix_ident(&iface), Span::call_site());
                let iface_name = Ident::new(&format!("{}_{}", &iface, "interface"), Span::call_site());
                quote! {
                    pub unsafe fn #name(#(#args),*) -> *mut super::#iface_mod::#iface_type {
                        let r = ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_marshal_constructor,
                            #interface_ident as _, #opcode, &super::#iface_mod::#iface_name as * const _ #(,#param_name_list)* );

                        #destroy_end

                        return r as _;
                    }
                }
            }
            else {
                quote! {
                    pub unsafe fn #name(#(#args),*) {
                        ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_marshal,
                            #interface_ident as _, #opcode #(,#param_name_list)*, std::ptr::null::<c_void>() );

                        #destroy_end
                    }
                }
            };
            quote! {

                #doc
                #func
            }
        },
        Side::Server => { quote!() }
    };

    opcode += 1;

    result

    }).collect::<Vec<_>>();

    let simple_desctr = if !has_destroy && interface.name != "wl_display" {
        let dname = Ident::new(
            &format!("{}_{}", interface.name, "destroy"),
            Span::call_site(),
        );
        quote! {
            pub unsafe fn #dname(#thisparam) {
                ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_destroy,
                                #interface_ident as _);
            }
        }
    } else {
        quote!()
    };

    quote! {
        pub unsafe fn #sud(#thisparam, user_data: *mut c_void) {
            ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_set_user_data,
                            #interface_ident as _, user_data);
        }

        pub unsafe fn #gud(#thisparam) -> * mut c_void {
            return ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_get_user_data,
                            #interface_ident as _);
        }

        pub unsafe fn #gv(#thisparam) -> u32 {
            return ffi_dispatch!(WAYLAND_CLIENT_HANDLE, wl_proxy_get_version,
                            #interface_ident as _);
        }

        #add_l_stub

        #simple_desctr

        #(#stubs)*
    }
}

fn generate_code<'a, T: std::clone::Clone + Iterator<Item = &'a Protocol>>(
    protocols: T,
) -> TokenStream {
    let modules = protocols.clone().flat_map(|protocol| {
        let pname = Ident::new(&protocol.name, Span::call_site());

        let interfaces_code = protocol.interfaces.iter().map(move |iface| {
            let doc_attr = iface.description.as_ref().map(description_to_doc_attr);
            let mod_name = Ident::new(&iface.name, Span::call_site());
            let iface_name = Ident::new(&iface.name, Span::call_site());

            let enums = &iface.enums;

            let event_handler_trait = gen_event_handler_trait(&iface_name, &iface.events, Side::Client);
            let interface = generate_interface(&iface);

            let stubs = generate_stubs(&iface, Side::Client);

            quote! {
                #doc_attr
                pub mod #mod_name {
                    use std::os::raw::{c_char, c_void, c_int};
                    use super::super::{types_null, NULLPTR};
                    use super::super::super::sys::common::{wl_interface, wl_array, wl_argument, wl_message, wl_fixed_t};
                    use super::super::super::sys::client::*;

                    pub enum #iface_name {}

                    #(#enums)*

                    #interface

                    #event_handler_trait

                    #stubs
                }
            }
        });



        if protocol.name == "wayland" {
            quote! {
                pub mod #pname {
                    #(#interfaces_code)*
                }
            }
        }
        else { 
            let mut generic_stable_protocols = vec!["xdg_shell", "org_kde_kwin_outputdevice", "kde_output_device_v2"];
            generic_stable_protocols.retain(|i| *i!=protocol.name);
            let generic_includes = generic_stable_protocols.iter().map(|name| {let iname = Ident::new(name, Span::call_site()); quote!(use super::#iname::*;)});
            quote!{
                pub mod #pname {
                    use super::wayland::*;
                    #(#generic_includes)*
                    #(#interfaces_code)*
                }
            }
        }
    });

    let c_prefix = generate_interfaces_prefix(protocols);

    quote! {
        #c_prefix


        #(#modules)*
    }
}

use std::fs::*;
use std::path::PathBuf;

fn get_protocol_files<T: AsRef<Path>>(path: T) -> Vec<PathBuf> {
    let mut result: Vec<PathBuf> = vec![];

    for i in read_dir(path).unwrap() {
        let e = i.unwrap();
        let meta = e.metadata().unwrap();

        if meta.is_dir() {
            result.append(&mut get_protocol_files(e.path()));
        } else if meta.is_file()
            && e.path().extension().is_some()
            && e.path().extension().unwrap() == "xml"
        {
            result.push(e.path().clone());
        }
    }

    return result;
}

fn get_protocols<T: AsRef<Path>>(path: T) -> Vec<Protocol> {
    get_protocol_files(path)
        .iter()
        .flat_map(|f| {
            println!("cargo:rerun-if-changed={}", f.as_path().display());
            std::panic::catch_unwind(|| load_xml(f)).ok()
        })
        .fold(std::collections::HashMap::<String, Protocol>::new(), |mut pmap, protocol| {
            if pmap.get(&protocol.name).is_none() {
                pmap.insert(protocol.name.clone(), protocol.clone());
            }

            pmap
        })
        .values()
        .cloned()
        .collect()
}

fn main() {
    let protocols = get_protocols("./protocols");

    let out_dir_str = var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_str);

    let target = out_dir.join("client.rs");

    let mut out = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&target)
        .unwrap();

    let code = generate_code(protocols.iter());

    write!(&mut out, "{}", code).unwrap();

    let _ = Command::new("rustfmt").arg(&target).status();
}
