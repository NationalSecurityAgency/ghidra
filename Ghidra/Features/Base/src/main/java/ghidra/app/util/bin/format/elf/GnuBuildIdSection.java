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
package ghidra.app.util.bin.format.elf;

import static ghidra.app.util.bin.StructConverter.*;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Factory data type that marks up a Gnu Build-Id record from a 
 * ELF .note.gnu.build-id section
 */
public class GnuBuildIdSection extends FactoryStructureDataType {
	public static final String BUILD_ID_SECTION_NAME = ".note.gnu.build-id";
	private static final int MAX_SANE_STR_LENS = 1024;

	public static GnuBuildIdValues fromProgram(Program program) {
		MemoryBlock buildIdSection = program.getMemory().getBlock(BUILD_ID_SECTION_NAME);
		if (buildIdSection == null) {
			return null;
		}
		try (ByteProvider bp = MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(),
			buildIdSection)) {
			BinaryReader br = new BinaryReader(bp, !program.getMemory().isBigEndian());
			long nameLen = br.readNextUnsignedInt();
			long descLen = br.readNextUnsignedInt();
			int vendorType = br.readNextInt();
			if (nameLen > MAX_SANE_STR_LENS || descLen > MAX_SANE_STR_LENS) {
				return null;
			}
			String name = br.readNextAsciiString((int) nameLen);
			byte[] desc = br.readNextByteArray((int) descLen);
			return new GnuBuildIdValues(name, desc, vendorType);
		}
		catch (IOException e) {
			// fall thru and return null
		}
		return null;
	}

	public static class GnuBuildIdValues {
		private static final int SHA1_DESC_LEN = 20; // 160bit SHA1 == 20 bytes

		private String name; // ie. "gnu"
		private byte[] description; // the hash
		private int vendorType;

		private GnuBuildIdValues(String name, byte[] description, int vendorType) {
			this.name = name;
			this.description = description;
			this.vendorType = vendorType;
		}

		public String getName() {
			return name;
		}

		public byte[] getDescription() {
			return description;
		}

		public int getVendorType() {
			return vendorType;
		}

		public boolean isValid() {
			return "GNU".equals(name) && description.length == SHA1_DESC_LEN;
		}
	}

	private long sectionSize;

	/**
	 * Creates a new GnuBuildIdDataType instance.
	 * 
	 * @param dtm the {@link DataTypeManager} for the program
	 * @param sectionSize the size of the section (for bounds checking, assumes this
	 * is the only record in the section)
	 */
	public GnuBuildIdSection(DataTypeManager dtm, long sectionSize) {
		super("Gnu_BuildId", dtm);
		this.sectionSize = sectionSize;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == dataMgr) {
			return this;
		}
		return new GnuBuildIdSection(dtm, sectionSize);
	}

	@Override
	protected void populateDynamicStructure(MemBuffer buf, Structure es) {
		try {
			long nameLen = buf.getUnsignedInt(0);
			long descLen = buf.getUnsignedInt(4);
			if (nameLen > MAX_SANE_STR_LENS || descLen > MAX_SANE_STR_LENS ||
				nameLen + descLen + 12 /* sizeof int fields */ > sectionSize) {
				return;
			}

			es.add(DWORD, "namesz", "Length of name field");
			es.add(DWORD, "descsz", "Length of description field");
			es.add(DWORD, "type", "Vendor specific type");
			if (nameLen > 0) {
				es.add(StringDataType.dataType, (int) nameLen, "name", "Build-id vendor name");
			}
			if (descLen > 0) {
				es.add(new ArrayDataType(BYTE, (int) descLen, BYTE.getLength(), dataMgr),
					"description", "Build-id value");
			}
		}
		catch (MemoryAccessException e) {
			// ignore and drop thru with partial defined structure type
		}

	}

	@Override
	protected Structure setCategoryPath(Structure struct, MemBuffer buf) {
		try {
			struct.setCategoryPath(new CategoryPath("/ELF"));
		}
		catch (DuplicateNameException e) {
			// ignore - will not happen
		}
		return struct;
	}

}
