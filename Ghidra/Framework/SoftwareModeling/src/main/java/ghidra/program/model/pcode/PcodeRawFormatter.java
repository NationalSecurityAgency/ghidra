/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
