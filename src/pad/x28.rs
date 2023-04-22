use std::fmt::Write;
use std::str::FromStr;

use crate::x121::X121Addr;

#[derive(PartialEq, Debug)]
pub enum X28Command {
    Selection(X121Addr),
    ClearRequest,
    Read(Vec<u8>),
    Set(Vec<(u8, u8)>),
    Status,
    ClearInvitation,
    Exit,
}

impl FromStr for X28Command {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let pair: Vec<&str> = s.trim().splitn(2, ' ').collect();

        let command = pair[0].to_uppercase();
        let rest = if pair.len() > 1 { pair[1] } else { "" };

        match &command[..] {
            "CALL" => {
                if rest.is_empty() {
                    return Err("addr required, dude!".into());
                }

                match X121Addr::from_str(rest) {
                    Ok(addr) => Ok(X28Command::Selection(addr)),
                    Err(_) => Err("invalid addr".into()),
                }
            }
            "CLR" | "CLEAR" => Ok(X28Command::ClearRequest),
            "PAR?" | "PAR" | "PARAMETER" | "READ" => {
                let params = parse_read_params(rest)?;

                Ok(X28Command::Read(params))
            }
            "SET" => {
                let params = parse_set_params(rest)?;

                if params.is_empty() {
                    return Err("params required!".into());
                }

                Ok(X28Command::Set(params))
            }
            "STAT" | "STATUS" => Ok(X28Command::Status),
            "ICLR" | "ICLEAR" => Ok(X28Command::ClearInvitation),
            "EXIT" => Ok(X28Command::Exit),
            _ => Err("unrecognized command".into()),
        }
    }
}

// Cisco and RAD both implement subtly different handling of invalid input, this
// is closer to the RAD implementation which is more straightforward to implement.
fn parse_read_params(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();

    if s.is_empty() {
        return Ok(vec![]);
    }

    s.split(',')
        .map(|a| u8::from_str(a.trim()).map_err(|_| "invalid param".into()))
        .collect()
}

fn parse_set_params(s: &str) -> Result<Vec<(u8, u8)>, String> {
    let s = s.trim();

    if s.is_empty() {
        return Ok(vec![]);
    }

    s.split(',')
        .map(|a| {
            let Some((param, value)) = a.split_once(':') else {
                return Err("invalid set argument".into());
            };

            let Ok(param) = u8::from_str(param.trim()) else {
                return Err("invalid param".into());
            };

            let Ok(value) = u8::from_str(value.trim()) else {
                return Err("invalid value".into());
            };

            Ok((param, value))
        })
        .collect()
}

pub fn format_params(params: &[(u8, Option<u8>)]) -> String {
    let mut s = String::new();

    for &(param, value) in params {
        if !s.is_empty() {
            s.push_str(", ");
        }

        match value {
            Some(value) => write!(&mut s, "{param}:{value}"),
            None => write!(&mut s, "{param}:INV"),
        };
    }

    s
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
    fn from_str_read() {
        assert_eq!(X28Command::from_str("par?"), Ok(X28Command::Read(vec![])));
        assert_eq!(
            X28Command::from_str("par? 1"),
            Ok(X28Command::Read(vec![1]))
        );
        assert_eq!(
            X28Command::from_str("par? 1,2"),
            Ok(X28Command::Read(vec![1, 2]))
        );
        assert_eq!(
            X28Command::from_str("par? 1, 2"),
            Ok(X28Command::Read(vec![1, 2]))
        );
    }

    #[test]
    fn from_str_read_invalid() {
        assert!(X28Command::from_str("par? a").is_err());
        assert!(X28Command::from_str("par? 1,a").is_err());
        assert!(X28Command::from_str("par? ,").is_err());
    }

    #[test]
    fn from_str_set() {
        assert_eq!(
            X28Command::from_str("set 1:1"),
            Ok(X28Command::Set(vec![(1, 1)]))
        );
        assert_eq!(
            X28Command::from_str("set 1:1,2:2"),
            Ok(X28Command::Set(vec![(1, 1), (2, 2)]))
        );
        assert_eq!(
            X28Command::from_str("set 1: 1, 2 : 2"),
            Ok(X28Command::Set(vec![(1, 1), (2, 2)]))
        );
    }

    #[test]
    fn from_str_set_invalid() {
        assert!(X28Command::from_str("set").is_err());
        assert!(X28Command::from_str("set 1").is_err());
        assert!(X28Command::from_str("set 1:a").is_err());
        assert!(X28Command::from_str("set a").is_err());
        assert!(X28Command::from_str("set ,").is_err());
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
