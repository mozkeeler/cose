use std::string::String;
use std::collections::BTreeMap;

pub enum CborType<'a> {
    UInt(u64),
    NInt(i64),
    BStr(&'a [u8]),
    TStr(&'a String),
    Arr(&'a [CborType<'a>]),
    Map(&'a BTreeMap<i64, CborType<'a>>), // TODO: find out what key value range we really have to support
}

/// Given a vector of bytes to append to, a tag to use, and an unsigned value to encode, uses the
/// CBOR unsigned integer encoding to represent the given value.
fn common_encode_unsigned(output: &mut Vec<u8>, tag: u8, value: u64) {
    assert!(tag < 8);
    let shifted_tag = tag << 5;
    match value {
        0 ... 23 => {
            output.push(shifted_tag | (value as u8));
        },
        24 ... 255 => {
            output.push(shifted_tag | 24);
            output.push(value as u8);
        },
        256 ... 65535 => {
            output.push(shifted_tag | 25);
            output.push((value >> 8) as u8);
            output.push((value & 255) as u8);
        },
        65536 ... 4294967295 => {
            output.push(shifted_tag | 26);
            output.push((value >> 24) as u8);
            output.push(((value >> 16) & 255) as u8);
            output.push(((value >> 8) & 255) as u8);
            output.push((value & 255) as u8);
        },
        _ => {
            output.push(shifted_tag | 27);
            output.push((value >> 56) as u8);
            output.push(((value >> 48) & 255) as u8);
            output.push(((value >> 40) & 255) as u8);
            output.push(((value >> 32) & 255) as u8);
            output.push(((value >> 24) & 255) as u8);
            output.push(((value >> 16) & 255) as u8);
            output.push(((value >> 8) & 255) as u8);
            output.push((value & 255) as u8);
        }
    };
}

/// The major type is 0. For values 0 through 23, the 5 bits of additional information is just the
/// value of the unsigned number. For values representable in one byte, the additional information
/// has the value 24. If two bytes are necessary, the value is 25. If four bytes are necessary, the
/// value is 26. If 8 bytes are necessary, the value is 27. The following bytes are the value of the
/// unsigned number in as many bytes were indicated in network byte order (big endian).
fn encode_unsigned(output: &mut Vec<u8>, unsigned: u64) {
    common_encode_unsigned(output, 0, unsigned);
}

/// The major type is 1. The encoding is the same as for positive (i.e. unsigned) integers, except
/// the value encoded is -1 minus the value of the negative number.
fn encode_negative(output: &mut Vec<u8>, negative: i64) {
    assert!(negative < 0);
    let value_to_encode: u64 = (-1 - negative) as u64;
    common_encode_unsigned(output, 1, value_to_encode);
}

/// The major type is 2. The length of the data is encoded as with positive integers, followed by
/// the actual data.
fn encode_bstr(output: &mut Vec<u8>, bstr: &[u8]) {
    common_encode_unsigned(output, 2, bstr.len() as u64);
    for byte in bstr {
        output.push(*byte);
    }
}

/// The major type is 3. The length is as with bstr. The UTF-8-encoded bytes of the string follow.
fn encode_tstr(output: &mut Vec<u8>, tstr: &String) {
    let utf8_bytes = tstr.as_bytes();
    common_encode_unsigned(output, 3, utf8_bytes.len() as u64);
    for byte in utf8_bytes {
        output.push(*byte);
    }
}

/// The major type is 4. The number of items is encoded as with positive integers. Then follows the
/// encodings of the items themselves.
fn encode_array(output: &mut Vec<u8>, array: &[CborType]) {
    common_encode_unsigned(output, 4, array.len() as u64);
    for element in array {
        let element_encoded = element.serialize();
        for byte in element_encoded {
            output.push(byte);
        }
    }
}

/// The major type is 5. The number of pairs is encoded as with positive integers. Then follows the
/// encodings of each key, value pair. In Canonical CBOR, the keys must be sorted lowest value to
/// highest.
fn encode_map(output: &mut Vec<u8>, map: &BTreeMap<i64, CborType>) {
    common_encode_unsigned(output, 5, map.len() as u64);
    for (key, value) in map { // The implementation gives us this in sorted order already.
        let key_encoded = if *key < 0 {
            CborType::NInt(*key).serialize()
        } else {
            CborType::UInt(*key as u64).serialize()
        };
        for byte in key_encoded {
            output.push(byte);
        }
        let value_encoded = value.serialize();
        for byte in value_encoded {
            output.push(byte);
        }
    }
}

impl<'a> CborType<'a> {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        match *self {
            CborType::UInt(unsigned) => encode_unsigned(&mut bytes, unsigned),
            CborType::NInt(negative) => encode_negative(&mut bytes, negative),
            CborType::BStr(bstr) => encode_bstr(&mut bytes, bstr),
            CborType::TStr(tstr) => encode_tstr(&mut bytes, tstr),
            CborType::Arr(arr) => encode_array(&mut bytes, arr),
            CborType::Map(map) => encode_map(&mut bytes, map),
        };
        bytes
    }
}

#[test]
fn test_uint() {
    struct Testcase {
        value: u64,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: 0, expected: vec![0] },
        Testcase { value: 1, expected: vec![1] },
        Testcase { value: 10, expected: vec![0x0a] },
        Testcase { value: 23, expected: vec![0x17] },
        Testcase { value: 24, expected: vec![0x18, 0x18] },
        Testcase { value: 25, expected: vec![0x18, 0x19] },
        Testcase { value: 100, expected: vec![0x18, 0x64] },
        Testcase { value: 1000, expected: vec![0x19, 0x03, 0xe8] },
        Testcase { value: 1000000, expected: vec![0x1a, 0x00, 0x0f, 0x42, 0x40] },
        Testcase { value: 1000000000000,
                   expected: vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00] },
        Testcase { value: 18446744073709551615,
                   expected: vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff] },
    ];
    for testcase in testcases {
        let cbor = CborType::UInt(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_nint() {
    struct Testcase {
        value: i64,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: -1, expected: vec![0x20], },
        Testcase { value: -10, expected: vec![0x29], },
        Testcase { value: -100, expected: vec![0x38, 0x63], },
        Testcase { value: -1000, expected: vec![0x39, 0x03, 0xe7], },
        Testcase { value: -1000000, expected: vec![0x3a, 0x00, 0x0f, 0x42, 0x3f], },
        Testcase { value: -4611686018427387903,
                   expected: vec![0x3b, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe] },
    ];
    for testcase in testcases {
        let cbor = CborType::NInt(testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_bstr() {
    struct Testcase {
        value: Vec<u8>,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: vec![], expected: vec![0x40] },
        Testcase { value: vec![0x01, 0x02, 0x03, 0x04],
                   expected: vec![0x44, 0x01, 0x02, 0x03, 0x04] },
        Testcase { value: vec![0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                               0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                               0xaf, 0xaf, 0xaf],
                   expected: vec![0x58, 0x19, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                                  0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf,
                                  0xaf, 0xaf, 0xaf, 0xaf, 0xaf] },

    ];
    for testcase in testcases {
        let cbor = CborType::BStr(testcase.value.as_slice());
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_tstr() {
    struct Testcase {
        value: String,
        expected: Vec<u8>,
    }
    let testcases: Vec<Testcase> = vec![
        Testcase { value: String::new(), expected: vec![0x60] },
        Testcase { value: String::from("a"), expected: vec![0x61, 0x61] },
        Testcase { value: String::from("IETF"), expected: vec![0x64, 0x49, 0x45, 0x54, 0x46] },
        Testcase { value: String::from("\"\\"), expected: vec![0x62, 0x22, 0x5c] },
        Testcase { value: String::from("水"), expected: vec![0x63, 0xe6, 0xb0, 0xb4] },
    ];
    for testcase in testcases {
        let cbor = CborType::TStr(&testcase.value);
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_arr() {
    struct Testcase<'a> {
        value: Vec<CborType<'a>>,
        expected: Vec<u8>,
    }
    let nested_arr_1 = vec![CborType::UInt(2), CborType::UInt(3)];
    let nested_arr_2 = vec![CborType::UInt(4), CborType::UInt(5)];
    let testcases: Vec<Testcase> = vec![
        Testcase { value: vec![], expected: vec![0x80] },
        Testcase { value: vec![CborType::UInt(1), CborType::UInt(2), CborType::UInt(3)],
                   expected: vec![0x83, 0x01, 0x02, 0x03] },
        Testcase { value: vec![CborType::UInt(1),
                               CborType::Arr(nested_arr_1.as_slice()),
                               CborType::Arr(nested_arr_2.as_slice())],
                   expected: vec![0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05] },
        Testcase { value: vec![CborType::UInt(1), CborType::UInt(2), CborType::UInt(3),
                               CborType::UInt(4), CborType::UInt(5), CborType::UInt(6),
                               CborType::UInt(7), CborType::UInt(8), CborType::UInt(9),
                               CborType::UInt(10), CborType::UInt(11), CborType::UInt(12),
                               CborType::UInt(13), CborType::UInt(14), CborType::UInt(15),
                               CborType::UInt(16), CborType::UInt(17), CborType::UInt(18),
                               CborType::UInt(19), CborType::UInt(20), CborType::UInt(21),
                               CborType::UInt(22), CborType::UInt(23), CborType::UInt(24),
                               CborType::UInt(25)],
                   expected: vec![0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                  0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19] },
    ];
    for testcase in testcases {
        let cbor = CborType::Arr(&testcase.value.as_slice());
        assert_eq!(testcase.expected, cbor.serialize());
    }
}

#[test]
fn test_map() {
    let empty_map: BTreeMap<i64, CborType> = BTreeMap::new();
    assert_eq!(vec![0xa0], CborType::Map(&empty_map).serialize());

    let mut positive_map: BTreeMap<i64, CborType> = BTreeMap::new();
    positive_map.insert(20, CborType::UInt(10));
    positive_map.insert(10, CborType::UInt(20));
    positive_map.insert(15, CborType::UInt(15));
    assert_eq!(vec![0xa3, 0x0a, 0x14, 0x0f, 0x0f, 0x14, 0x0a],
               CborType::Map(&positive_map).serialize());

    let mut negative_map: BTreeMap<i64, CborType> = BTreeMap::new();
    negative_map.insert(-4, CborType::UInt(10));
    negative_map.insert(-1, CborType::UInt(20));
    negative_map.insert(-5, CborType::UInt(15));
    negative_map.insert(-6, CborType::UInt(10));
    assert_eq!(vec![0xa4, 0x25, 0x0a, 0x24, 0x0f, 0x23, 0x0a, 0x20, 0x14],
               CborType::Map(&negative_map).serialize());

    let mut mixed_map: BTreeMap<i64, CborType> = BTreeMap::new();
    mixed_map.insert(0, CborType::UInt(10));
    mixed_map.insert(-10, CborType::UInt(20));
    mixed_map.insert(15, CborType::UInt(15));
    assert_eq!(vec![0xa3, 0x29, 0x14, 0x00, 0x0a, 0x0f, 0x0f],
               CborType::Map(&mixed_map).serialize());
}
