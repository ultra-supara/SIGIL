#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IROp {
    pub op: String,
    pub dst: Option<String>,
    pub src: Option<String>,
    pub src2: Option<String>,
    pub symbol: Option<String>,
    pub source_address: Option<u64>,
    pub text: String,
}

impl IROp {
    pub fn mov(dst: &str, src: &str, source_address: u64, text: &str) -> Self {
        Self {
            op: "Mov".to_string(),
            dst: Some(dst.to_string()),
            src: Some(src.to_string()),
            src2: None,
            symbol: None,
            source_address: Some(source_address),
            text: text.to_string(),
        }
    }

    pub fn binary(
        op: &str,
        dst: &str,
        src: &str,
        src2: &str,
        source_address: u64,
        text: &str,
    ) -> Self {
        Self {
            op: op.to_string(),
            dst: Some(dst.to_string()),
            src: Some(src.to_string()),
            src2: Some(src2.to_string()),
            symbol: None,
            source_address: Some(source_address),
            text: text.to_string(),
        }
    }

    pub fn external_call(symbol: &str, source_address: u64, text: &str) -> Self {
        Self {
            op: "ExternalCall".to_string(),
            dst: None,
            src: None,
            src2: None,
            symbol: Some(symbol.to_string()),
            source_address: Some(source_address),
            text: text.to_string(),
        }
    }

    pub fn ret(source_address: u64, text: &str) -> Self {
        Self {
            op: "Return".to_string(),
            dst: None,
            src: None,
            src2: None,
            symbol: None,
            source_address: Some(source_address),
            text: text.to_string(),
        }
    }

    pub fn unsupported(source_address: u64, text: &str) -> Self {
        Self {
            op: "Unsupported".to_string(),
            dst: None,
            src: None,
            src2: None,
            symbol: None,
            source_address: Some(source_address),
            text: text.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub name: String,
    pub ops: Vec<IROp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub blocks: Vec<BasicBlock>,
}
