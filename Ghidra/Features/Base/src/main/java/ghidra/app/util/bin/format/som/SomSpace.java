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
 * Represents a SOM {@code space_dictionary_record} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomSpace implements StructConverter {

	/** The size in bytes of a {@link SomSpace} */
	public static final int SIZE = 0x24;

	private String name;
	private boolean isLoadable;
	private boolean isDefined;
	private boolean isPrivate;
	private boolean hasIntermediateCode;
	private boolean isThreadSpecific;
	private int reserved;
	private int sortKey;
	private int reserved2;
	private int spaceNumber;
	private int subspaceIndex;
	private long subspaceQuantity;
	private int loaderFixIndex;
	private long loaderFixQuantity;
	private int initPointerIndex;
	private long initPointerQuantity;


	/**
	 * Creates a new {@link SomSpace}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param spaceStringsLocation The starting index of the space strings
	 * @throws IOException if there was an IO-related error
	 */
	public SomSpace(BinaryReader reader, long spaceStringsLocation) throws IOException {
		name = reader.readAsciiString(spaceStringsLocation + reader.readNextUnsignedInt());
		int bitfield = reader.readNextInt();
		reserved2 = bitfield & 0xff;
		sortKey = (bitfield >> 8) & 0xff;
		reserved = (bitfield >> 16) & 0x7ff;
		isThreadSpecific = ((bitfield >> 27) & 0x1) != 0;
		hasIntermediateCode = ((bitfield >> 28) & 0x1) != 0;
		isPrivate = ((bitfield >> 29) & 0x1) != 0;
		isDefined = ((bitfield >> 30) & 0x1) != 0;
		isLoadable = ((bitfield >> 31) & 0x1) != 0;
		spaceNumber = reader.readNextInt();
		subspaceIndex = reader.readNextInt();
		subspaceQuantity = reader.readNextUnsignedInt();
		loaderFixIndex = reader.readNextInt();
		loaderFixQuantity = reader.readNextUnsignedInt();
		initPointerIndex = reader.readNextInt();
		initPointerQuantity = reader.readNextUnsignedInt();

	}

	/**
	 * {@return the space name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return whether or not the space is loadable}
	 */
	public boolean isLoadable() {
		return isLoadable;
	}

	/**
	 * {@return whether or not the space is defined within the file}
	 */
	public boolean isDefined() {
		return isDefined;
	}

	/**
	 * {@return whether or not the space is not sharable}
	 */
	public boolean isPrivate() {
		return isPrivate;
	}

	/**
	 * {@return whether or not the space contains intermediate code}
	 */
	public boolean hasIntermediateCode() {
		return hasIntermediateCode;
	}

	/**
	 * {@return whether or not the space is thread specific}
	 */
	public boolean isThreadSpecific() {
		return isThreadSpecific;
	}

	/**
	 * {@return the first reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return the sort key for the space}
	 */
	public int getSortKey() {
		return sortKey;
	}

	/**
	 * {@return the second reserved value}
	 */
	public int getReserved2() {
		return reserved2;
	}

	/**
	 * {@return the space index}
	 */
	public int getSpaceNumber() {
		return spaceNumber;
	}

	/**
	 * {@return the index into the subspace dictionary}
	 */
	public int getSubspaceIndex() {
		return subspaceIndex;
	}

	/**
	 * {@return the number of subspaces in the space}
	 */
	public long getSubspaceQuantity() {
		return subspaceQuantity;
	}

	/**
	 * {@return the load fix index}
	 */
	public int getLoaderFixIndex() {
		return loaderFixIndex;
	}

	/**
	 * {@return the load fix quantity}
	 */
	public long getLoaderFixQuantity() {
		return loaderFixQuantity;
	}

	/**
	 * {@return the index into data (init) pointer array}
	 */
	public int getInitPonterIndex() {
		return initPointerIndex;
	}

	/**
	 * {@return the number of data (init) pointers}
	 */
	public long getInitPointerQuantity() {
		return initPointerQuantity;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType("space_dictionary_record", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "name", "index to subspace name");
		try {
			struct.addBitField(DWORD, 1, "is_loadable", "space is loadable");
			struct.addBitField(DWORD, 1, "is_defined", "space is defined within file");
			struct.addBitField(DWORD, 1, "is_private", "space is not sharable");
			struct.addBitField(DWORD, 1, "has_intermediate_code", "contain intermediate code");
			struct.addBitField(DWORD, 1, "is_tspecific", "is thread specific");
			struct.addBitField(DWORD, 11, "reserved", "reserved for future expansion");
			struct.addBitField(DWORD, 8, "sort_key", "sort key for space");
			struct.addBitField(DWORD, 8, "reserved2", "reserved for future expansion");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "space_number", "space index");
		struct.add(DWORD, "subspace_index", "index into subspace dictionary");
		struct.add(DWORD, "subspace_quantity", "number of subspaces in space");
		struct.add(DWORD, "loader_fix_index", "loader usage");
		struct.add(DWORD, "loader_fix_quantity", "loader usage");
		struct.add(DWORD, "init_pointer_index", "index into data(initialization) pointer array");
		struct.add(DWORD, "init_pointer_quantity", "number of data (init) pointers");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
