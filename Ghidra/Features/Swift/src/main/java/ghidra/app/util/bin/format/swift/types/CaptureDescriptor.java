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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a Swift {@code CaptureDescriptor} structure
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/RemoteInspection/Records.h">swift/RemoteInspection/Records.h</a> 
 */
public final class CaptureDescriptor extends SwiftTypeMetadataStructure {

	/**
	 * The size (in bytes) of a {@link CaptureDescriptor} structure
	 */
	public static final int SIZE = 12;

	private int numCaptureTypes;
	private int numMetadataSources;
	private int numBindings;

	private List<CaptureTypeRecord> captureTypeRecords = new ArrayList<>();
	private List<MetadataSourceRecord> metadataSourceRecords = new ArrayList<>();

	/**
	 * Creates a new {@link CaptureDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public CaptureDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		numCaptureTypes = reader.readNextInt();
		numMetadataSources = reader.readNextInt();
		numBindings = reader.readNextInt();

		for (int i = 0; i < numCaptureTypes; i++) {
			captureTypeRecords.add(new CaptureTypeRecord(reader));
		}

		for (int i = 0; i < numMetadataSources; i++) {
			metadataSourceRecords.add(new MetadataSourceRecord(reader));
		}
	}

	/**
	 * {@return the number of capture types}
	 */
	public int getNumCaptureTypes() {
		return numCaptureTypes;
	}

	/**
	 * {@return the number of metadata sources}
	 */
	public int getNumMetadataSources() {
		return numMetadataSources;
	}

	/**
	 * {@return the number of bindings}
	 */
	public int getNumBindings() {
		return numBindings;
	}

	/**
	 * {@return the {@link List} of {@link CaptureTypeRecord}s}
	 */
	public List<CaptureTypeRecord> getCaptureTypeRecords() {
		return captureTypeRecords;
	}

	/**
	 * {@return the {@link List} of {@link MetadataSourceRecord}s}
	 */
	public List<MetadataSourceRecord> getMetadataSourceRecords() {
		return metadataSourceRecords;
	}

	@Override
	public String getStructureName() {
		return CaptureDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "capture descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(CATEGORY_PATH, getStructureName(), 0);
		struct.add(DWORD, "NumCaptureTypes", "");
		struct.add(DWORD, "NumMetadataSources", "");
		struct.add(DWORD, "NumBindings", "");
		return struct;
	}

}
