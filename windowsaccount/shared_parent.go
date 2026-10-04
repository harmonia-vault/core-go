package windowsaccount

const sharedParentMetadataMask uint32 = 0x000200a0 // READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE

// BU receives metadata/traverse only on this directory. There is deliberately no
// inheritance, list-directory, read-data, write, delete, ownership or DACL right.
const sharedParentDirectory = `O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x200a0;;;BU)`
