package ghidra.app.util.bin.format.elf;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class RustUtilities {

    public static boolean isRust(MemoryBlock rodataBlock, SymbolTable symbolTable) {
        // Check .rodata section for known Rust string
        if (rodataBlock != null) {
            try {
                byte[] bytes = new byte[(int) rodataBlock.getSize()];
                rodataBlock.getBytes(rodataBlock.getStart(), bytes);
                String content = new String(bytes);
                if (content.contains("rust_eh_personality")) {
                    return true;
                }
            } catch (Exception e) {
                // Ignore and continue
            }
        }

        // Check symbol names for Rust-specific patterns
        if (symbolTable != null) {
            SymbolIterator symbols = symbolTable.getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                String name = symbol.getName();
                if (name == null) continue;

                if (name.contains("rust_eh_personality") ||
                    name.contains("core::") ||
                    name.contains("alloc::") ||
                    name.contains("std::")) {
                    return true;
                }
            }
        }

        return false;
    }
}

