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
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift entry point 
 */
public final class EntryPoint extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of an {@link EntryPoint} structure
	 */
	public static final int SIZE = 4;

	private int entryPoint;

	/**
	 * Creates a new {@link EntryPoint}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public EntryPoint(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		entryPoint = reader.readNextInt();
	}

	/**
	 * Gets the entry point
	 * 
	 * @return The entry point
	 */
	public int getEntryPoint() {
		return entryPoint;
	}

	@Override
	public String getStructureName() {
		return EntryPoint.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "entry point";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return SwiftUtils.PTR_RELATIVE;
	}

}
