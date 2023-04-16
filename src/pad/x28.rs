use std::str::FromStr;

use crate::x121::X121Addr;

#[derive(PartialEq, Debug)]
pub enum X28Command {
    Selection(X121Addr),
    ClearRequest,
    Status,
    ClearInvitation,
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
                    Ok(addr) => Ok(X28Command::Selection(addr)),
                    Err(_) => Err("invalid addr".into()),
                }
            }
            "CLR" | "CLEAR" => Ok(X28Command::ClearRequest),
            "STAT" | "STATUS" => Ok(X28Command::Status),
            "ICLR" | "ICLEAR" => Ok(X28Command::ClearInvitation),
            "EXIT" => Ok(X28Command::Exit),
            _ => Err("unrecognized command".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_selection_valid() {
        assert_eq!(
            X28Command::from_str("call 12345"),
            Ok(X28Command::Selection(X121Addr::from_str("12345").unwrap()))
        );
    }

    #[test]
    fn from_str_selection_invalid() {
        assert!(X28Command::from_str("call").is_err());
    }

    #[test]
    fn from_str_clear_request() {
        assert_eq!(X28Command::from_str("clr"), Ok(X28Command::ClearRequest));
        assert_eq!(X28Command::from_str("clear"), Ok(X28Command::ClearRequest));
    }

    #[test]
    fn from_str_status() {
        assert_eq!(X28Command::from_str("stat"), Ok(X28Command::Status));
        assert_eq!(X28Command::from_str("status"), Ok(X28Command::Status));
    }

    #[test]
    fn from_str_clear_invitation() {
        assert_eq!(
            X28Command::from_str("iclr"),
            Ok(X28Command::ClearInvitation)
        );
        assert_eq!(
            X28Command::from_str("iclear"),
            Ok(X28Command::ClearInvitation)
        );
    }

    #[test]
    fn from_str_exit() {
        assert_eq!(X28Command::from_str("exit"), Ok(X28Command::Exit));
    }
}
