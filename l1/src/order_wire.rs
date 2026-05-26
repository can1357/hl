use core::fmt;

use serde::{Deserialize, Serialize};

pub const WIRE_DECIMALS: u32 = 8;
pub const COMPACT_ORDER_ENTRY_BASE_LEN: usize = 21;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrderWireSerde {
    pub a: u32,
    pub b: bool,
    pub p: String,
    pub s: String,
    pub r: bool,
    pub t: OrderTypeWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cloid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireDecimal(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TimeInForce {
    Alo,
    Ioc,
    Gtc,
    FrontendMarket,
    LiquidationMarket,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OrderTypeWire {
    #[serde(rename = "limit")]
    Limit { tif: TimeInForce },
    #[serde(rename = "trigger")]
    Trigger(TriggerWire),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TriggerWire {
    #[serde(rename = "isMarket")]
    pub is_market: bool,
    #[serde(rename = "triggerPx")]
    pub trigger_px: String,
    pub tpsl: TpSl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpSl {
    Tp,
    Sl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalOrderType {
    Limit { tif: TimeInForce },
    Trigger { is_market: bool, trigger_px: WireDecimal, tpsl: TpSl },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalOrder {
    pub asset: u32,
    pub is_buy: bool,
    pub limit_px: WireDecimal,
    pub sz: WireDecimal,
    pub reduce_only: bool,
    pub order_type: InternalOrderType,
    pub cloid: Option<Cloid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactOrderBatch {
    pub tag: CompactOrderBatchTag,
    pub aux: CompactOrderAux,
    pub orders: Vec<InternalOrder>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactOrderBatchTag {
    RmpSerde = 0,
    CustomSlice = 1,
    NestedCustomSlice = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactOrderAux {
    pub encoded: u32,
    pub kind: u32,
    pub extended_index: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderWireError {
    InvalidDecimal,
    DecimalTooPrecise,
    DecimalOverflow,
    InvalidCloid,
    InvalidTif(u8),
    UnknownOrderTypeVariant(u8),
    CustomSliceBadLen,
    CustomSliceAuxByteMismatch,
    UnsupportedTaggedEncoding(u8),
}

impl OrderWireSerde {
    pub fn to_internal(&self) -> Result<InternalOrder, OrderWireError> {
        let cloid = match self.c.as_deref() {
            Some(value) => Some(Cloid::parse(value)?),
            None => None,
        };

        Ok(InternalOrder {
            asset: self.a,
            is_buy: self.b,
            limit_px: WireDecimal::parse(&self.p)?,
            sz: WireDecimal::parse(&self.s)?,
            reduce_only: self.r,
            order_type: self.t.to_internal()?,
            cloid,
        })
    }

    pub fn from_internal(order: &InternalOrder) -> Self {
        Self {
            a: order.asset,
            b: order.is_buy,
            p: order.limit_px.to_string(),
            s: order.sz.to_string(),
            r: order.reduce_only,
            t: OrderTypeWire::from_internal(order.order_type),
            c: order.cloid.map(|cloid| cloid.to_string()),
        }
    }
}

impl OrderTypeWire {
    pub fn to_internal(&self) -> Result<InternalOrderType, OrderWireError> {
        Ok(match self {
            Self::Limit { tif } => InternalOrderType::Limit { tif: *tif },
            Self::Trigger(trigger) => InternalOrderType::Trigger {
                is_market: trigger.is_market,
                trigger_px: WireDecimal::parse(&trigger.trigger_px)?,
                tpsl: trigger.tpsl,
            },
        })
    }

    pub fn from_internal(order_type: InternalOrderType) -> Self {
        match order_type {
            InternalOrderType::Limit { tif } => Self::Limit { tif },
            InternalOrderType::Trigger { is_market, trigger_px, tpsl } => Self::Trigger(TriggerWire {
                is_market,
                trigger_px: trigger_px.to_string(),
                tpsl,
            }),
        }
    }
}

impl WireDecimal {
    pub fn parse(s: &str) -> Result<Self, OrderWireError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(OrderWireError::InvalidDecimal);
        }

        let mut seen_dot = false;
        let mut frac_digits = 0u32;
        let mut value = 0u64;
        let mut seen_digit = false;

        for &byte in bytes {
            match byte {
                b'0'..=b'9' => {
                    seen_digit = true;
                    if seen_dot {
                        frac_digits += 1;
                        if frac_digits > WIRE_DECIMALS {
                            return Err(OrderWireError::DecimalTooPrecise);
                        }
                    }
                    value = value
                        .checked_mul(10)
                        .and_then(|v| v.checked_add((byte - b'0') as u64))
                        .ok_or(OrderWireError::DecimalOverflow)?;
                }
                b'.' if !seen_dot => seen_dot = true,
                _ => return Err(OrderWireError::InvalidDecimal),
            }
        }

        if !seen_digit {
            return Err(OrderWireError::InvalidDecimal);
        }

        for _ in frac_digits..WIRE_DECIMALS {
            value = value.checked_mul(10).ok_or(OrderWireError::DecimalOverflow)?;
        }
        Ok(Self(value))
    }

    pub fn write_to(&self, out: &mut String) {
        let mut value = self.0;
        let mut scale = WIRE_DECIMALS;
        while scale != 0 && value % 10 == 0 {
            value /= 10;
            scale -= 1;
        }

        if scale == 0 {
            push_u64(out, value);
            return;
        }

        let divisor = pow10(scale);
        push_u64(out, value / divisor);
        out.push('.');
        let frac = value % divisor;
        let mut place = divisor / 10;
        while place > 1 && frac < place {
            out.push('0');
            place /= 10;
        }
        push_u64(out, frac);
    }
}

impl fmt::Display for WireDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.write_to(&mut s);
        f.write_str(&s)
    }
}

impl Cloid {
    pub fn parse(s: &str) -> Result<Self, OrderWireError> {
        let bytes = s.as_bytes();
        if bytes.len() != 34 || bytes[0] != b'0' || bytes[1] != b'x' {
            return Err(OrderWireError::InvalidCloid);
        }

        let mut out = [0u8; 16];
        for i in 0..16 {
            let hi = hex_val(bytes[2 + 2 * i]).ok_or(OrderWireError::InvalidCloid)?;
            let lo = hex_val(bytes[3 + 2 * i]).ok_or(OrderWireError::InvalidCloid)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    pub fn write_to(&self, out: &mut String) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push_str("0x");
        for &byte in &self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

impl fmt::Display for Cloid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(34);
        self.write_to(&mut s);
        f.write_str(&s)
    }
}

pub fn decode_tagged_order_wire(bytes: &[u8]) -> Result<CompactOrderBatch, OrderWireError> {
    let (&tag, rest) = bytes.split_first().ok_or(OrderWireError::CustomSliceBadLen)?;
    match tag {
        1 => decode_custom_slice(rest),
        0 | 2 => Err(OrderWireError::UnsupportedTaggedEncoding(tag)),
        other => Err(OrderWireError::UnknownOrderTypeVariant(other)),
    }
}

pub fn encode_custom_slice(batch: &CompactOrderBatch, out: &mut Vec<u8>) -> Result<(), OrderWireError> {
    out.push(CompactOrderBatchTag::CustomSlice as u8);
    out.extend_from_slice(&batch.aux.encoded.to_be_bytes());
    out.push(0);
    for order in &batch.orders {
        encode_compact_order(order, out)?;
    }
    Ok(())
}

pub fn decode_custom_slice(bytes: &[u8]) -> Result<CompactOrderBatch, OrderWireError> {
    if bytes.len() < 5 {
        return Err(OrderWireError::CustomSliceBadLen);
    }

    let encoded = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let aux = if encoded >= 3 {
        let extended_index = encoded - 3;
        if extended_index >= 100_000_001 {
            return Err(OrderWireError::CustomSliceBadLen);
        }
        CompactOrderAux { encoded, kind: 3, extended_index: Some(extended_index) }
    } else {
        CompactOrderAux { encoded, kind: encoded, extended_index: None }
    };

    match bytes[4] {
        0 => {
            let orders = decode_compact_orders(&bytes[5..])?;
            Ok(CompactOrderBatch { tag: CompactOrderBatchTag::CustomSlice, aux, orders })
        }
        2 => Err(OrderWireError::UnsupportedTaggedEncoding(2)),
        _ => Err(OrderWireError::CustomSliceAuxByteMismatch),
    }
}

pub fn decode_compact_orders(mut bytes: &[u8]) -> Result<Vec<InternalOrder>, OrderWireError> {
    let mut orders = Vec::new();
    while !bytes.is_empty() {
        let (order, used) = decode_compact_order(bytes)?;
        orders.push(order);
        bytes = &bytes[used..];
    }
    Ok(orders)
}

pub fn decode_compact_order(bytes: &[u8]) -> Result<(InternalOrder, usize), OrderWireError> {
    if bytes.len() < COMPACT_ORDER_ENTRY_BASE_LEN {
        return Err(OrderWireError::CustomSliceBadLen);
    }

    let asset = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let limit_px = WireDecimal(u64::from_be_bytes(bytes[4..12].try_into().unwrap()));
    let sz = WireDecimal(u64::from_be_bytes(bytes[12..20].try_into().unwrap()));
    let flags = bytes[20];
    let type_code = (flags >> 2) & 0x0f;
    let has_trigger_px = (flags & 0x30) == 0x10;
    let has_cloid = (flags & 0x40) != 0;

    let mut pos = COMPACT_ORDER_ENTRY_BASE_LEN;
    let trigger_px = if has_trigger_px {
        if bytes.len() < pos + 8 {
            return Err(OrderWireError::CustomSliceBadLen);
        }
        let value = WireDecimal(u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap()));
        pos += 8;
        Some(value)
    } else {
        None
    };

    let cloid = if has_cloid {
        if bytes.len() < pos + 16 {
            return Err(OrderWireError::CustomSliceBadLen);
        }
        let mut value = [0u8; 16];
        value.copy_from_slice(&bytes[pos..pos + 16]);
        pos += 16;
        Some(Cloid(value))
    } else {
        None
    };

    let order_type = compact_type_code_to_order_type(type_code, trigger_px)?;
    Ok((InternalOrder {
        asset,
        is_buy: (flags & 1) != 0,
        limit_px,
        sz,
        reduce_only: (flags & 2) != 0,
        order_type,
        cloid,
    }, pos))
}

pub fn encode_compact_order(order: &InternalOrder, out: &mut Vec<u8>) -> Result<(), OrderWireError> {
    let (type_code, trigger_px) = compact_type_code_from_order_type(order.order_type)?;
    let mut flags = (type_code << 2) | u8::from(order.is_buy) | (u8::from(order.reduce_only) << 1);
    if order.cloid.is_some() {
        flags |= 0x40;
    }

    out.extend_from_slice(&order.asset.to_be_bytes());
    out.extend_from_slice(&order.limit_px.0.to_be_bytes());
    out.extend_from_slice(&order.sz.0.to_be_bytes());
    out.push(flags);
    if let Some(trigger_px) = trigger_px {
        out.extend_from_slice(&trigger_px.0.to_be_bytes());
    }
    if let Some(cloid) = order.cloid {
        out.extend_from_slice(&cloid.0);
    }
    Ok(())
}

fn compact_type_code_to_order_type(type_code: u8, trigger_px: Option<WireDecimal>) -> Result<InternalOrderType, OrderWireError> {
    Ok(match type_code {
        1 => InternalOrderType::Limit { tif: TimeInForce::Alo },
        2 => InternalOrderType::Limit { tif: TimeInForce::Gtc },
        3 => InternalOrderType::Limit { tif: TimeInForce::Ioc },
        4 => InternalOrderType::Trigger { is_market: true, trigger_px: trigger_px.ok_or(OrderWireError::CustomSliceBadLen)?, tpsl: TpSl::Tp },
        5 => InternalOrderType::Trigger { is_market: false, trigger_px: trigger_px.ok_or(OrderWireError::CustomSliceBadLen)?, tpsl: TpSl::Tp },
        6 => InternalOrderType::Trigger { is_market: true, trigger_px: trigger_px.ok_or(OrderWireError::CustomSliceBadLen)?, tpsl: TpSl::Sl },
        7 => InternalOrderType::Trigger { is_market: false, trigger_px: trigger_px.ok_or(OrderWireError::CustomSliceBadLen)?, tpsl: TpSl::Sl },
        8 => InternalOrderType::Limit { tif: TimeInForce::FrontendMarket },
        9 => InternalOrderType::Limit { tif: TimeInForce::LiquidationMarket },
        other => return Err(OrderWireError::UnknownOrderTypeVariant(other)),
    })
}

fn compact_type_code_from_order_type(order_type: InternalOrderType) -> Result<(u8, Option<WireDecimal>), OrderWireError> {
    Ok(match order_type {
        InternalOrderType::Limit { tif: TimeInForce::Alo } => (1, None),
        InternalOrderType::Limit { tif: TimeInForce::Gtc } => (2, None),
        InternalOrderType::Limit { tif: TimeInForce::Ioc } => (3, None),
        InternalOrderType::Trigger { is_market: true, trigger_px, tpsl: TpSl::Tp } => (4, Some(trigger_px)),
        InternalOrderType::Trigger { is_market: false, trigger_px, tpsl: TpSl::Tp } => (5, Some(trigger_px)),
        InternalOrderType::Trigger { is_market: true, trigger_px, tpsl: TpSl::Sl } => (6, Some(trigger_px)),
        InternalOrderType::Trigger { is_market: false, trigger_px, tpsl: TpSl::Sl } => (7, Some(trigger_px)),
        InternalOrderType::Limit { tif: TimeInForce::FrontendMarket } => (8, None),
        InternalOrderType::Limit { tif: TimeInForce::LiquidationMarket } => (9, None),
    })
}

fn push_u64(out: &mut String, mut value: u64) {
    if value == 0 {
        out.push('0');
        return;
    }

    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    while value != 0 {
        pos -= 1;
        buf[pos] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    out.push_str(core::str::from_utf8(&buf[pos..]).unwrap());
}

const fn pow10(exp: u32) -> u64 {
    let mut value = 1u64;
    let mut i = 0;
    while i < exp {
        value *= 10;
        i += 1;
    }
    value
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
