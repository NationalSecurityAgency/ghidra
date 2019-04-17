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

	private boolean isFatHeader;
	private boolean hasMoreSections;
	private boolean initLocals;
	private int maxStack; // Max number of items on operand stack
	private int methodSize; // Size of method body (code)
	private int localVarSigTok;
	
	private static final byte CorILMethod_TinyFormat = 0x2;
	private static final byte CorILMethod_FatFormat = 0x3;
	private static final byte CorILMethod_MoreSects = 0x8;
	private static final byte CorILMethod_InitLocals = 0x10;
	
	public CliMethodDef(Address addr, BinaryReader reader) throws IOException {
		this.addr = addr;

		// Read first byte, see if tiny or fat.
		byte one = reader.readNextByte();
		if ((one & CorILMethod_FatFormat) == CorILMethod_FatFormat) {
			isFatHeader = true;
			if ((one & CorILMethod_MoreSects) == CorILMethod_MoreSects)
				hasMoreSections = true;
			if ((one & CorILMethod_InitLocals) == CorILMethod_InitLocals)
				initLocals = true;
			byte two = reader.readNextByte(); // TODO: need to read byte two? Seems to only have header length (in the wrong order?? >_<)
			maxStack = reader.readNextShort();
			methodSize = reader.readNextInt();
			localVarSigTok = reader.readNextInt();
		}
		else if ((one & CorILMethod_TinyFormat) == CorILMethod_TinyFormat) {
			isFatHeader = false;
			hasMoreSections = false;
			initLocals = false;
			maxStack = 8;
			methodSize = (((one & ~0x3) & 0xff) >> 2); // Mask off first 2 bits, right shift to get 6 length bits. 0xff mask to convert to right sign.
		}
	}
	
	private void fillTinyHeaderType(Structure struct) {
		struct.add(BYTE, "Size+Flags", "L.S. Bits 0:1 Flags, Bits 2:7 Size of method in Bytes");
	}
	
	private void fillFatHeaderType(Structure struct) {
		struct.add( WORD, "Size+Flags", "L.S. Bits 0:3 Size of hdr in B, Bits 4:15 Flags");
		struct.add( WORD, "MaxStack", "Maximum number of items on the operand stack");
		struct.add(DWORD, "CodeSize", "Size of actual method body in B");
		struct.add(DWORD, "LocalVarSigTok", "Signature for the local variables of the method. 0 means no locals. References standalone signature in Metadata tables, which references #Blob heap.");
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType(new CategoryPath(PATH), "MethodDefHdr_" + addr, 0);
		if (isFatHeader) {
			fillFatHeaderType(struct);
		}
		else {
			fillTinyHeaderType(struct);
		}
		return struct;
	}

	public int getMethodSize() {
		return methodSize;
	}

	public boolean hasMoreSections() {
		return hasMoreSections;
	}

}
