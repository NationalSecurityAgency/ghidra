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
package ghidra.app.util.bin.format.pe.cli.methods;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CliMethodDef implements StructConverter {

	public static final String PATH = "/PE/CLI/Methods/MethodDefs";

	private Address addr;

	public enum HeaderFormat {
		Fat, Tiny
	}

	private int headerFlags;
	private HeaderFormat headerFormat;
	private int headerSize; // Size of this header
	private int maxStack; // Max number of items on operand stack
	private int methodSize; // Size of method body (code)
	private int localVarSigTok;

	private static final int CLIMETHODDEF_HEADER_FLAGS_SHIFT = 0x08;
	private static final int CLIMETHODDEF_HEADER_FLAGS_MASK = 0x0FFF;
	private static final int CLIMETHODDEF_HEADER_SIZE_SHIFT = 0x0C;
	private static final int CLIMETHODDEF_HEADER_SIZE_FAT_MULTIPLIER = 0x04;

	private static final byte CorILMethod_TinyFormat = 0x2;
	private static final byte CorILMethod_FatFormat = 0x3;
	private static final byte CorILMethod_MoreSects = 0x8;
	private static final byte CorILMethod_InitLocals = 0x10;

	public CliMethodDef(Address addr, BinaryReader reader) throws IOException {
		this.addr = addr;

		// Read first byte, see if tiny or fat.
		int firstByte = reader.readNextUnsignedByte();
		if ((firstByte & CorILMethod_FatFormat) == CorILMethod_FatFormat) {
			headerFormat = HeaderFormat.Fat;

			// The header flags are stored across 12 bits, the top 4 bits
			// indicate the size of the header
			headerFlags =
				(firstByte << CLIMETHODDEF_HEADER_FLAGS_SHIFT) + reader.readNextUnsignedByte();
			headerSize = headerFlags >> CLIMETHODDEF_HEADER_SIZE_SHIFT;
			headerFlags = (headerFlags & CLIMETHODDEF_HEADER_FLAGS_MASK);

			// The raw header size bits indicate: "Size of this header
			// expressed as the count of 4-bytes integers occupied."
			headerSize = headerSize * CLIMETHODDEF_HEADER_SIZE_FAT_MULTIPLIER;

			maxStack = reader.readNextShort();
			methodSize = reader.readNextInt();
			localVarSigTok = reader.readNextInt();
		}
		else if ((firstByte & CorILMethod_TinyFormat) == CorILMethod_TinyFormat) {
			headerFormat = HeaderFormat.Tiny;
			headerSize = 1;
			headerFlags = 0;
			maxStack = 8;
			methodSize = (((firstByte & ~0x3) & 0xff) >> 2); // Mask off first 2 bits, right shift to get 6 length bits. 0xff mask to convert to right sign.
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct;

		if (headerFormat == HeaderFormat.Fat) {
			struct = new StructureDataType(new CategoryPath(PATH), "MethodDefHdr_Fat", 0);
			struct.add(WORD, "Size+Flags", "L.S. Bits 0:3 Size of hdr in bytes, Bits 4:15 Flags");
			struct.add(WORD, "MaxStack", "Maximum number of items on the operand stack");
			struct.add(DWORD, "CodeSize", "Size of actual method body in bytes");
			struct.add(DWORD, "LocalVarSigTok",
				"Signature for the local variables of the method. 0 means no locals. References standalone signature in Metadata tables, which references #Blob heap.");
		}
		else {
			struct = new StructureDataType(new CategoryPath(PATH), "MethodDefHdr_Tiny", 0);
			struct.add(BYTE, "Size+Flags", "L.S. Bits 0:1 Flags, Bits 2:7 Size of method in Bytes");
		}

		return struct;
	}

	public int getMethodSize() {
		return methodSize;
	}

	public boolean hasMoreSections() {
		return (headerFlags & CorILMethod_MoreSects) == CorILMethod_MoreSects;
	}

	public boolean hasLocals() {
		return (headerFlags & CorILMethod_InitLocals) == CorILMethod_InitLocals;
	}

	public HeaderFormat getHeaderFormat() {
		return headerFormat;
	}
}
