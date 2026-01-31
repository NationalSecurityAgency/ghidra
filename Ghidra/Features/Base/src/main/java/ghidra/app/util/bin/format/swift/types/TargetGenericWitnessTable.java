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
package ghidra.app.util.bin.format.swift.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class TargetGenericWitnessTable extends SwiftTypeMetadataStructure {

	private int witnessTableSizeInWords;
	private int witnessTablePrivateSizeInWordsAndRequiresInstantiation;
	private int instantiator;
	private int privateData;

	/**
	 * Creates a new {@link TargetGenericWitnessTable}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetGenericWitnessTable(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		witnessTableSizeInWords = reader.readNextUnsignedShort();
		witnessTablePrivateSizeInWordsAndRequiresInstantiation = reader.readNextUnsignedShort();
		instantiator = reader.readNextInt();
		privateData = reader.readNextInt();
	}

	/**
	 * {@return the size of the witness table in words}
	 * <p>
	 * The amount is copied from the witness table template into the instantiated witness table.
	 */
	public int getWitnessTableSizeInWords() {
		return witnessTableSizeInWords;
	}

	/**
	 * {@return the amount of private storage to allocate before the address point, in words}
	 * <p>
	 * This memory is zeroed out in the instantiated witness table template. The low bit is used to
	 * indicate whether this witness table is known to require instantiation.
	 */
	public int getWitnessTablePrivateSizeInWordsAndRequiresInstantiation() {
		return witnessTablePrivateSizeInWordsAndRequiresInstantiation;
	}

	/**
	 * {@return the instantiation function, which is called after the template is copied}
	 */
	public int getInstantiator() {
		return instantiator;
	}

	/**
	 * {@return the private data for the instantiator}
	 * <p>
	 * Might be null with building with {@code -disable-preallocated-instantiation-caches}.
	 */
	public int getPrivateData() {
		return privateData;
	}

	@Override
	public String getStructureName() {
		return TargetGenericWitnessTable.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "generic witness table";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(WORD, "WitnessTableSizeInWords", "The size of the witness table in words.");
		struct.add(WORD, "WitnessTablePrivateSizeInWordsAndRequiresInstantiation",
			"The amount of private storage to allocate before the address point, in words.");
		struct.add(SwiftUtils.PTR_RELATIVE, "Instantiator",
			"The instantiation function, which is called after the template is copied.");
		struct.add(SwiftUtils.PTR_RELATIVE, "PrivateData", "Private data for the instantiator.");
		return struct;
	}
}
