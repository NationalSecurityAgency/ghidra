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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code subspace_dictionary_record} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomSubspace implements StructConverter {

	/** The size in bytes of a {@link SomSubspace} */
	public static final int SIZE = 0x28;

	private int spaceIndex;
	private int accessControlBits;
	private boolean memoryResident;
	private boolean dupCommon;
	private boolean isCommon;
	private boolean isLoadable;
	private int quadrant;
	private boolean initiallyFrozen;
	private boolean isFirst;
	private boolean codeOnly;
	private int sortKey;
	private boolean replicateInit;
	private boolean continuation;
	private boolean isThreadSpecific;
	private boolean isComdat;
	private int reserved;
	private int fileLocInitValue;
	private long initializationLength;
	private long subspaceStart;
	private long subspaceLength;
	private int reserved2;
	private int alignment;
	private String name;
	private int fixupRequestIndex;
	private long fixupRequestQuantity;


	/**
	 * Creates a new {@link SomSubspace}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param spaceStringsLocation The starting index of the space strings
	 * @throws IOException if there was an IO-related error
	 */
	public SomSubspace(BinaryReader reader, long spaceStringsLocation) throws IOException {
		spaceIndex = reader.readNextInt();
		int bitfield = reader.readNextInt();
		reserved = bitfield & 0x0f;
		isComdat = ((bitfield >> 4) & 0x1) != 0;
		isThreadSpecific = ((bitfield >> 5) & 0x1) != 0;
		continuation = ((bitfield >> 6) & 0x1) != 0;
		replicateInit = ((bitfield >> 7) & 0x1) != 0;
		sortKey = (bitfield >> 8) & 0xff;
		codeOnly = ((bitfield >> 16) & 0x1) != 0;
		isFirst = ((bitfield >> 17) & 0x1) != 0;
		initiallyFrozen = ((bitfield >> 18) & 0x1) != 0;
		quadrant = (bitfield >> 19) & 0x3;
		isLoadable = ((bitfield >> 21) & 0x1) != 0;
		isCommon = ((bitfield >> 22) & 0x1) != 0;
		dupCommon = ((bitfield >> 23) & 0x1) != 0;
		memoryResident = ((bitfield >> 24) & 0x1) != 0;
		accessControlBits = (bitfield >> 25) & 0x7f;
		fileLocInitValue = reader.readNextInt();
		initializationLength = reader.readNextUnsignedInt();
		subspaceStart = reader.readNextUnsignedInt();
		subspaceLength = reader.readNextUnsignedInt();
		bitfield = reader.readNextInt();
		alignment = bitfield & 0x7ffffff;
		reserved2 = (bitfield >> 27) & 0x1f;
		name = reader.readAsciiString(spaceStringsLocation + reader.readNextUnsignedInt());
		fixupRequestIndex = reader.readNextInt();
		fixupRequestQuantity = reader.readNextUnsignedInt();

	}

	/**
	 * {@return the space index}
	 */
	public int getSpaceIndex() {
		return spaceIndex;
	}

	/**
	 * {@return the access control bits for PDIR entries}
	 */
	public int getAccessControlBits() {
		return accessControlBits;
	}

	/**
	 * {@return whether or not to lock in memory during execution}
	 */
	public boolean isMemoryResident() {
		return memoryResident;
	}

	/**
	 * {@return whether or not data name clashes are allowed}
	 */
	public boolean isDupCommon() {
		return dupCommon;
	}

	/**
	 * {@return whether or not the subspace is a common}
	 */
	public boolean isCommon() {
		return isCommon;
	}

	/**
	 * {@return whether or not the subspace is loadable}
	 */
	public boolean isLoadable() {
		return isLoadable;
	}

	/**
	 * {@return the quadrant request}
	 */
	public int getQuadrant() {
		return quadrant;
	}

	/**
	 * {@return whether or not the subspace must be locked into memory when the OS is booted}
	 */
	public boolean isInitiallyFrozen() {
		return initiallyFrozen;
	}

	/**
	 * {@return whether or not this must be the first subspace}
	 */
	public boolean isFirst() {
		return isFirst;
	}

	/**
	 * {@return whether or not the subspace must contain only code}
	 */
	public boolean isCodeOnly() {
		return codeOnly;
	}

	/**
	 * {@return the sort key for the subspace}
	 */
	public int getSortKey() {
		return sortKey;
	}

	/**
	 * {@return whether or not init values are replicated to fill {@code subspace_length}}
	 */
	public boolean isReplicateInit() {
		return replicateInit;
	}

	/**
	 * {@return whether or not this subspace is a continuation}
	 */
	public boolean isContinuation() {
		return continuation;
	}

	/**
	 * {@return whether or not the subspace is thread specific}
	 */
	public boolean isThreadSpecific() {
		return isThreadSpecific;
	}

	/**
	 * {@return whether or not this is for COMDAT subspaces}
	 */
	public boolean isComdat() {
		return isComdat;
	}

	/**
	 * {@return the first reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return the file location or initialization value}
	 */
	public int getFileLocInitValue() {
		return fileLocInitValue;
	}

	/**
	 * {@return the initialization length}
	 */
	public long getInitializationLength() {
		return initializationLength;
	}

	/**
	 * {@return the starting offset}
	 */
	public long getSubspaceStart() {
		return subspaceStart;
	}

	/**
	 * {@return the number of bytes defined by this subspace}
	 */
	public long getSubspaceLength() {
		return subspaceLength;
	}

	/**
	 * {@return the second reserved value}
	 */
	public int getReserved2() {
		return reserved2;
	}

	/**
	 * {@return the alignment required for the subspace}
	 */
	public int getAlignment() {
		return alignment;
	}

	/**
	 * {@return the subspace name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the index into fixup array}
	 */
	public int getFixupRequestIndex() {
		return fixupRequestIndex;
	}

	/**
	 * {@return the number of fixup requests}
	 */
	public long getFixupRequestQuantity() {
		return fixupRequestQuantity;
	}

	/**
	 * {@return whether or not this subspace is readable}
	 */
	public boolean isRead() {
		return getAccessControlType() < 4;
	}

	/**
	 * {@return whether or not this subspace is writeable}
	 */
	public boolean isWrite() {
		return getAccessControlType() == 1 || getAccessControlType() == 3;
	}

	/**
	 * {@return whether or not this subspace is executable}
	 */
	public boolean isExecute() {
		return getAccessControlType() >= 2;
	}

	/**
	 * {@return the "type" part of the access control bits}
	 */
	private int getAccessControlType() {
		return (accessControlBits >> 4) & 0x3;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("subspace_dictionary_record", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "space_index", "");
		try {
			struct.addBitField(DWORD, 7, "access_control_bits", "access for PDIR entries");
			struct.addBitField(DWORD, 1, "memory_resident", "lock in memory during execution");
			struct.addBitField(DWORD, 1, "dup_common", "data name clashes allowed");
			struct.addBitField(DWORD, 1, "is_common", "subspace is a common");
			struct.addBitField(DWORD, 1, "is_loadable", "");
			struct.addBitField(DWORD, 2, "quadrant", "quadrant request");
			struct.addBitField(DWORD, 1, "initially_frozen",
				"must be locked into memory when OS is booted");
			struct.addBitField(DWORD, 1, "is_first", "must be first subspace");
			struct.addBitField(DWORD, 1, "code_only", "must contain only code");
			struct.addBitField(DWORD, 8, "sort_key", "subspace sort key");
			struct.addBitField(DWORD, 1, "replicate_init",
				"init values replicated to fill subspace_length");
			struct.addBitField(DWORD, 1, "continuation", "subspace is a continuation");
			struct.addBitField(DWORD, 1, "is_tspecific", "is thread specific?");
			struct.addBitField(DWORD, 1, "is_comdat", "Is for COMDAT subspaces?");
			struct.addBitField(DWORD, 4, "reserved", "");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "file_loc_init_value", "file location or initialization value");
		struct.add(DWORD, "initialization_length", "");
		struct.add(DWORD, "subspace_start", "starting offset");
		struct.add(DWORD, "subspace_length", "number of bytes defined by this subspace");
		try {
			struct.addBitField(DWORD, 5, "reserved2", "");
			struct.addBitField(DWORD, 27, "alignment",
				"alignment required for the subspace (largest alignment requested for any item in the subspace)");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "name", "index of subspace name");
		struct.add(DWORD, "fixup_request_index", "index into fixup array");
		struct.add(DWORD, "fixup_request_quantity", "number of fixup requests");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
