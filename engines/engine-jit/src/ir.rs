/// Mask pattern operations
#[derive(Debug, Clone)]
pub enum MaskOp {
    Literal { byte: u8 },
    CharClass { class: CharClass },
    Range { start: u8, end: u8 },
    Repeat { op: Box<MaskOp>, min: u32, max: u32 },
    Alternation { choices: Vec<MaskOp> },
    Concat { ops: Vec<MaskOp> },
}

#[derive(Debug, Clone, Copy)]
pub enum CharClass {
    Lowercase,  // ?l = a-z
    Uppercase,  // ?u = A-Z
    Digit,      // ?d = 0-9
    HexLower,   // ?h = 0-9 a-f
    HexUpper,   // ?H = 0-9 A-F
    Special,    // ?s = !@#$%^&*()_+-=[]{}|;':\",./<>?~
    All,        // ?a = ?l + ?u + ?d + ?s
    Custom,     // ?1, ?2, ?3 = custom charsets
}

/// Rule operations for password mutation
#[derive(Debug, Clone)]
pub enum RuleOp {
    /// Delete first N characters
    DeleteFirst(u32),
    /// Delete last N characters
    DeleteLast(u32),
    /// Delete at position
    DeleteAt(u32),
    /// Keep first N characters
    TruncateLeft(u32),
    /// Keep last N characters
    TruncateRight(u32),
    /// Substitute character at position N with byte X
    Substitute(u32, u8),
    /// Insert byte X at position N
    Insert(u32, u8),
    /// Toggle case at position N
    Toggle(u32),
    /// Toggle case of all characters
    ToggleAll,
    /// Reverse string
    Reverse,
    /// Duplicate entire word
    Duplicate,
    /// Reflect (word + reverse(word))
    Reflect,
    /// Lowercase entire word
    Lowercase,
    /// Uppercase entire word
    Uppercase,
    /// Capitalize first letter
    Capitalize,
    /// Invert case
    Invert,
    /// Prepend string
    Prepend(Vec<u8>),
    /// Append string
    Append(Vec<u8>),
    /// Replace all X with Y
    ReplaceAll(u8, u8),
    /// Purge all occurrences of X
    Purge(u8),
    /// Duplicate first N characters
    DuplicateFirstN(u32),
    /// Duplicate last N characters
    DuplicateLastN(u32),
    /// Rotate left
    RotateLeft,
    /// Rotate right
    RotateRight,
}

#[derive(Debug, Clone)]
pub enum IrInstruction {
    Mask(MaskOp),
    Rule(RuleOp),
    Jump { target: usize },
    ConditionalJump { target: usize, condition: IrCondition },
    Return,
}

#[derive(Debug, Clone)]
pub enum IrCondition {
    LengthLessThan(u32),
    LengthGreaterThan(u32),
    Contains(u8),
    NotContains(u8),
}

#[derive(Debug, Clone, Default)]
pub struct IrProgram {
    pub instructions: Vec<IrInstruction>,
}

impl IrProgram {
    pub fn new() -> Self {
        IrProgram {
            instructions: Vec::new(),
        }
    }

    pub fn push(&mut self, inst: IrInstruction) {
        self.instructions.push(inst);
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}
