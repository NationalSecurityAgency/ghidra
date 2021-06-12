package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;

/**
 * Format the pcode in raw format. This is used to format patched pcode.
 * 
 * Roughly, something like this:
 * (space, offset, size) = OP (space, offset, size) // ... each (space, offset, size) is a varnode
 */
public class PcodeRawFormatter {
    public static String formatRaw(PcodeDataLike[] pcodes) {
        if (pcodes == null) {
            return null;
        }
        String result = "";
        boolean first = true;
        for (var pcode : pcodes) {
            if (first) {
                first = false;
            } else {
                result += "\n";
            }

            result += formatSingleRaw(pcode);
        }

        return result;
    }

    private static String formatVarnodeRaw(Varnode varnode) {
        if (varnode == null) {
            return "(null, 0x0, 0)";
        }
        Address addr = varnode.getAddress();
        String space = addr.getAddressSpace().getName();
        long offset = addr.getOffset();
        int size = varnode.getSize();

        return String.format("(%s,0x%x, %d)", space, offset, size);
    }

    public static String formatSingleRaw(PcodeDataLike pcode) {
        if (pcode == null) {
            return null;
        }

        int opcode = pcode.getOpcode();
        Varnode[] in = pcode.getInputs();
        Varnode out = pcode.getOutput();

        String opcodeMnemonic = PcodeOp.getMnemonic(opcode);

        String result = formatVarnodeRaw(out) + " = " + opcodeMnemonic;
        for (var inVarnode : in) {
            result += " " + formatVarnodeRaw(inVarnode);
        }
        return result;
    }
}
