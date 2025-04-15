package ghidra.app.util.bin;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class RustUtilities {

    private static final int MAX_SCAN_SIZE = 1024 * 1024; // 1MB

    public static boolean isRust(MemoryBlock rodataBlock, SymbolTable symbolTable) {
        //Safe .rodata scan
        if (rodataBlock != null) {
            try {
                long size = rodataBlock.getSize();
                int readSize = (int) Math.min(size, MAX_SCAN_SIZE);

                byte[] bytes = new byte[readSize];
                rodataBlock.getBytes(rodataBlock.getStart(), bytes);
                String content = new String(bytes);
                if (content.contains("rust_eh_personality")) {
                    return true;
                }
            } catch (Exception e) {
                // Ignore and continue
            }
        }

        //Symbol-based detection
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

