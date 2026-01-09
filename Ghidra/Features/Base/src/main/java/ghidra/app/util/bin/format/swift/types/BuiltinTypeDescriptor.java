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

/**
 * Represents a Swift {@code BuiltinTypeDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class BuiltinTypeDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link BuiltinTypeDescriptor} structure
	 */
	public static final int SIZE = 20;

	private String typeName;
	private int size;
	private int alignmentAndFlags;
	private int stride;
	private int numExtraInhabitants;

	/**
	 * Creates a new {@link BuiltinTypeDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public BuiltinTypeDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		typeName = reader.readNext(SwiftUtils::relativeString);
		size = reader.readNextInt();
		alignmentAndFlags = reader.readNextInt();
		stride = reader.readNextInt();
		numExtraInhabitants = reader.readNextInt();
	}

	/**
	 * {@return the type name}
	 */
	public String getTypeName() {
		return typeName;
	}

	/**
	 * {@return the size}
	 */
	public int getSize() {
		return size;
	}

	/**
	 * {@return the alignment and flags}
	 */
	public int getAlignmentAndFlags() {
		return alignmentAndFlags;
	}

	/**
	 * {@return the stride}
	 */
	public int getStride() {
		return stride;
	}

	/**
	 * {@return the number of extra inhabitants}
	 */
	public int getNumExtraInhabitants() {
		return numExtraInhabitants;
	}

	@Override
	public String getStructureName() {
		return BuiltinTypeDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "builtin type descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(SwiftUtils.PTR_STRING, "TypeName", "");
		struct.add(DWORD, "Size", "");
		struct.add(DWORD, "AlignmentAndFlags", "");
		struct.add(DWORD, "Stride", "");
		struct.add(DWORD, "NumExtraInhabitants", "");
		return struct;
	}

}
