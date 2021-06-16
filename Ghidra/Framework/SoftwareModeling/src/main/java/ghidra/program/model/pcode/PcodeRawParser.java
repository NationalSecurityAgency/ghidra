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

import java.util.regex.Pattern;
import java.util.stream.Stream;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.UnknownInstructionException;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Parses pcode that is in raw format (see {@link PcodeRawFormatter} for how the format should look like).
 * 
 * Usage:
 * 
 * PcodeRawParsedResult[] results = PcodeRawParser.parseRawPcode(addressFactory, "xxx");
 */
public class PcodeRawParser {

    private Pattern hexNumPattern = Pattern.compile(".*[abcdefABCDEF].*");
    private AddressFactory addressFactory;

    private PcodeRawParser(AddressFactory addressFactory) {
        this.addressFactory = addressFactory;
    }

    public static PcodeData[] parseRawPcode(
            AddressFactory addressFactory,
            String rawPcodeText) throws RuntimeException {
        if (rawPcodeText == null) {
            return null;
        }
        PcodeRawParser parser = new PcodeRawParser(addressFactory);
        return parser.parseRawPcode(rawPcodeText);
    }

    public static PcodeData parseSingleRawPcode(
        AddressFactory addressFactory,
        String rawPcodeText) throws RuntimeException {
        if (rawPcodeText == null) {
            return null;
        }
        PcodeRawParser parser = new PcodeRawParser(addressFactory);
        return parser.parseSingleRawPcode(rawPcodeText);
    }

    private long parseLong(String longString) {
        if (longString.startsWith("0x")) {
            return Long.parseLong(longString.substring(2), 16);
        } else if (hexNumPattern.matcher(longString).matches()) {
            return Long.parseLong(longString, 16);
        } else {
            return Long.parseLong(longString);
        }
    }

    private int parseInt(String intString) {
        if (intString.startsWith("0x")) {
            return Integer.parseInt(intString.substring(2), 16);
        } else if (hexNumPattern.matcher(intString).matches()) {
            return Integer.parseInt(intString, 16);
        } else {
            return Integer.parseInt(intString);
        }
    }

    private Varnode parseVarnode(String varnodeText) throws RuntimeException {
        // form: (space, offset, size)
            String[] parts = Stream.of(
                varnodeText
                .trim()
                .replace("(", "")
                .replace(")", "")
                .split(","))
                .map(part -> part.trim())
                .toArray(String[]::new);
            String space = parts[0];

            long offset = parseLong(parts[1]);
            int size = parseInt(parts[2]);

            if (space.equals("null")) {
                return null;
            }

            AddressSpace addrSpace = addressFactory.getAddressSpace(space);
            if (addrSpace == null) {
                String msg = String.format("Invalid address space name %s", space);
                throw new RuntimeException(msg);
            }

            Address addr = addressFactory.getAddress(addrSpace.getSpaceID(), offset);
            return new Varnode(addr, size);
    }

    private PcodeData parseSingleRawPcode(String pcodeText) throws RuntimeException {
        // form: varnode_out = OP varnode_in1, varnode_in2, ...
        try {
            Varnode varnodeOut = null;
            String[] rhsParts;
            if (pcodeText.indexOf("=") != -1) {
                String[] parts = Stream.of(pcodeText.split("=")).map(x -> x.trim()).toArray(String[]::new);
                varnodeOut = parseVarnode(parts[0]);
                rhsParts = parts[1].trim().split(" ");
            } else {
                rhsParts = pcodeText.trim().split(" ");
            }

            int opcode = PcodeOp.getOpcode(rhsParts[0]);
            rhsParts = Arrays.copyOfRange(rhsParts, 1, rhsParts.length);

            String inVarnodeText = String.join("", rhsParts)
                .replace("),", ") "); // spaces only between varnodes

            ArrayList<Varnode> varnodeIns = new ArrayList<>();

            for (var varnodeText : inVarnodeText.split(" ")) {
                varnodeIns.add(parseVarnode(varnodeText));
            }

            return new PcodeData(opcode, varnodeIns.toArray(Varnode[]::new), varnodeOut);
        } catch (UnknownInstructionException e) {
            throw new RuntimeException("Invalid Pcode OpCode: " + e.toString());
        } catch (Exception e) {
            throw new RuntimeException("Invalid Pcode Raw Expression");
        }
    }

    private PcodeData[] parseRawPcode(String pcodeText) throws RuntimeException {
        ArrayList<PcodeData> results = new ArrayList<>();

        for (var line : pcodeText.split("\n")) {
            line = line.trim();
            if (line.length() != 0) {
                results.add(parseSingleRawPcode(line));
            }
        }

        return results.toArray(PcodeData[]::new);
    }

}