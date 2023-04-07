//! X.25 packet sequence numbering.
//!
//! This module provides functionalty for handling X.25 packet sequence numbering.

/// X.25 packet sequence numbering scheme.
///
/// The sequence numbering scheme specifies the range of sequence numbers, and
/// in some cases the packet format as a result.
///
/// Only normal and extended schemes are currently supported, super extended is
/// not supported.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum X25Modulo {
    /// Numbers cycle through the entire range 0 to 7.
    Normal = 8,

    /// Numbers cycle through the entire range 0 to 127.
    Extended = 128,
}

/// Returns the next sequence number.
pub fn next_seq(seq: u8, modulo: X25Modulo) -> u8 {
    (seq + 1) % (modulo as u8)
}

/// X.25 flow control window.
#[derive(Debug)]
pub struct Window {
    start: u8,
    size: u8,
    modulo: X25Modulo,
    current: u8,
}

impl Window {
    pub fn new(size: u8, modulo: X25Modulo) -> Self {
        assert!(size > 0 && size < modulo as u8);

        Window {
            start: 0,
            size,
            modulo,
            current: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.current != (self.start + self.size) % (self.modulo as u8)
    }

    pub fn seq(&self) -> u8 {
        self.current
    }

    pub fn incr(&mut self) -> bool {
        if !self.is_open() {
            return false;
        }

        self.current = next_seq(self.current, self.modulo);

        true
    }

    #[must_use]
    pub fn update_start(&mut self, seq: u8) -> bool {
        if !is_seq_in_range(seq, self.start, self.current, self.modulo) {
            return false;
        }

        self.start = seq;

        true
    }
}

fn is_seq_in_range(seq: u8, start: u8, end: u8, modulo: X25Modulo) -> bool {
    if seq > (modulo as u8) - 1 {
        return false;
    }

    if start == end && seq == start {
        return true;
    }

    if start < end && seq >= start && seq <= end {
        return true;
    }

    if start > end && (seq >= start || seq <= end) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_next_seq() {
        assert_eq!(next_seq(0, X25Modulo::Normal), 1);
        assert_eq!(next_seq(7, X25Modulo::Normal), 0);
    }

    #[test]
    fn extended_next_seq() {
        assert_eq!(next_seq(0, X25Modulo::Extended), 1);
        assert_eq!(next_seq(127, X25Modulo::Extended), 0);
    }

    #[test]
    fn new_window_is_open() {
        let window = Window::new(2, X25Modulo::Normal);

        assert!(window.is_open());
    }

    #[test]
    fn window_is_closed_after_size_incr() {
        let mut window = Window::new(2, X25Modulo::Normal);

        window.incr();
        window.incr();

        assert!(!window.is_open());
    }

    #[test]
    fn window_incr_fails_if_window_closed() {
        let mut window = Window::new(2, X25Modulo::Normal);

        assert!(window.incr());
        assert!(window.incr());
        assert!(!window.incr());
    }

    #[test]
    fn window_is_reopened_after_update_start() {
        let mut window = Window::new(2, X25Modulo::Normal);

        window.incr();
        window.incr();

        assert!(!window.is_open());

        assert!(window.update_start(2));

        assert!(window.is_open());
    }

    #[test]
    fn window_update_start_must_be_valid() {
        let mut window = Window::new(2, X25Modulo::Normal);

        window.incr();
        window.incr();

        assert!(!window.is_open());

        assert!(!window.update_start(3));

        assert!(!window.is_open());
    }
}
