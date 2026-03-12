pub const windows = @cImport({
    @cDefine("UNICODE", "1");
    @cDefine("_UNICODE", "1");
    @cInclude("windows.h");
    @cInclude("psapi.h");
});

pub const RelocItem = packed struct {
    offset: u12,
    type: u4,
};



pub const ImageImportDescriptor = extern struct {
    OriginalFirstThunk: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    ForwarderChain: windows.DWORD,
    Name: windows.DWORD,
    FirstThunk: windows.DWORD,
};

pub const ImageImportByName = extern struct {
    Hint: windows.WORD,
    Name: windows.CHAR,
};

pub const ImageThunkData = extern union {
    ForwarderString: windows.ULONGLONG,
    Function: windows.ULONGLONG,
    Ordinal: windows.DWORD,
    AddressOfData: windows.DWORD,
};
