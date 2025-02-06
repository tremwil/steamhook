use pelite::pattern;
use pelite::pattern::Atom;
use pelite::pe32::{Pe, Rva};

// Patterns matching IPC ser/de functions

macro_rules! pattern_rvas {
    ($($name:ident: $pat:literal),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub struct PatternRVAs { $($name: Rva),* }

        impl PatternRVAs {
            pub fn new<'a>(pe_: &impl Pe<'a>) -> Self {
                let scanner_ = pe_.scanner();
                $(
                    let mut $name: Rva = 0;
                    if !scanner_.finds_code(pattern!($pat), std::slice::from_mut(&mut $name)) {
                        panic!("{}", concat!("pattern for ", stringify!($name), " (", $pat, ") not found"));
                    }
                )*
                Self { $($name),* }
            }
        }
    };
}

pattern_rvas! {
    utlbuf_seek: "' 55 8b ec [18] 8b ? 14 2b ? 0c",
    utlbuf_read_steamid: "' 55 8b ec [6] 8b ? 14 2b ? 0c 83 ? 08 7c",
    utlbuf_read_data: "' [5] 8b 7d 0c 8b ? 85 ? 78 ? 8a ? 1a",
    utlbuf_read_data_checked: "' 55 7b ec 8b ? 08 8b ? 10 8b ? 14 2b ? 0c",
    utlbuf_read_byte: "' 55 8b ec 51 ? 8b ? f6 ? 1b 01 75",
    utlbuf_read_cstr: "' 55 8b ec ? 8b ? 08 8b ? e8 $ { [3] 51 ? 8b ? f6 ? 1b 01 75 }",
    //utlbuf_read_cstr_checked: "",
    // utlbuf_write_steamid: "",
    // utlbuf_write_data: "",
    // utlbuf_write_cstr: "",
    // utlbuf_write_byte: "' 8b ? 04 2b ? 10 83 ? 01 7d ? 8b ? 20"
}

// impl PatternRVAs {
//     fn new(pe: &impl Pe) -> Self {
//         let utlbuf_read_steamuid = ;
//         pe.scanner().finds_code(
//             pattern!("55 8b ec [6] 8b ? 14 2b ? 0c 83 ? 08 7c"), &mut utlbuf_read_steamuid)
//             .then(|| utlbuf_read_steamuid)
//             .expect(format!("pattern not found: utl_read_steamid ()")
//     }
// }

const UTLBUF_READ_STEAMID: &[Atom] = pattern!("55 8b ec [6] 8b ? 14 2b ? 0c 83 ? 08 7c");

const UTLBUF_READ_DATA: &[Atom] = pattern!("[5] 8b 7d 0c 8b ? 85 ? 78 ? 8a ? 1a");

const UTLBUF_READ_DATA_CHECKED: &[Atom] = pattern!("55 7b ec 8b ? 08 8b ? 10 8b ? 14 2b ? 0c");

const UTLBUF_READ_BYTE: &[Atom] = pattern!("55 8b ec 51 ? 8b ? f6 ? 1b 01 75");

const UTLBUF_READ_CSTR: &[Atom] =
    pattern!("55 8b ec ? 8b ? 08 8b ? e8 $ { [3] 51 ? 8b ? f6 ? 1b 01 75 }");

const UTLBUF_READ_CSTR_CHECKED: &[Atom] =
    pattern!("55 8b ec ? 8b ? 08 8b ? e8 $ { [3] 51 ? 8b ? f6 ? 1b 01 75 }");

const UTLBUF_SEEK: &[Atom] = pattern!("");

const UTLBUF_WRITE_STEAMID: &[Atom] = pattern!("");

const UTLBUF_WRITE_DATA: &[Atom] = pattern!("");

const UTLBUF_WRITE_STR: &[Atom] = pattern!("");

const UTLBUF_WRITE_BYTE: &[Atom] = pattern!("");
