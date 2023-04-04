use std::str::FromStr;

use crate::x121::X121Addr;

pub enum X28Command {
    Call(X121Addr),
    Clear,
    Status,
    Exit,
}

impl FromStr for X28Command {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let pair: Vec<&str> = s.trim().splitn(2, ' ').collect();

        let command = pair[0].to_uppercase();
        let rest = if pair.len() > 1 { Some(pair[1]) } else { None };

        match &command[..] {
            "CALL" => {
                let addr = rest.unwrap_or("").trim();

                if addr.is_empty() {
                    return Err("addr required, dude!".into());
                }

                match X121Addr::from_str(addr) {
                    Ok(addr) => Ok(X28Command::Call(addr)),
                    Err(_) => Err("invalid addr".into()),
                }
            }
            "CLR" | "CLEAR" => Ok(X28Command::Clear),
            "STAT" | "STATUS" => Ok(X28Command::Status),
            "EXIT" => Ok(X28Command::Exit),
            _ => Err("unrecognized command".into()),
        }
    }
}
