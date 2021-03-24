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
package ghidra.app.util.bin.format.pe.cli.streams;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * The Blob stream contains ???.
 * When the stream is present, the first entry is always the byte 0x00.
 * This stream may contain garbage in its unreachable parts.
 */
public class CliStreamBlob extends CliAbstractStream {

	protected Map<Integer, CliBlob> blobMap;

	/**
	 * Gets the name of this stream.
	 *
	 * @return The name of this stream.
	 */
	public static String getName() {
		return "#Blob";
	}

	/**
	 * Creates a new Blob stream.
	 *
	 * @param header The stream header associated with this stream.
	 * @param offset The reader offset where this stream starts.
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is used to read the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliStreamBlob(CliStreamHeader header, long offset, int rva, BinaryReader reader)
			throws IOException {
		super(header, offset, rva, reader);

		blobMap = new LinkedHashMap<>();
	}

	@Override
	public boolean parse() throws IOException {
		reader.setPointerIndex(offset);

		// First byte is always 0x00
		reader.readNextByte();

		int bytesRead = 1;
		while (bytesRead < header.getSize()) {
			CliBlob blob = new CliBlob(bytesRead, reader);
			if (blob.getContentsSize() > 0) {
				blobMap.put(bytesRead, blob);
			}
			bytesRead += blob.getSize();
		}

		return true;
	}

	/**
	 * Gets the blob at the given index.
	 *
	 * @param index The index of the blob to get.
	 * @return The blob at the given index.  Could be null if the index was invalid or
	 *   there was a problem reading the blob.
	 */
	public CliBlob getBlob(int index) {
		return blobMap.get(index);
	}

	/**
	 * Updates the blob at the given address with the new blob.
	 *
	 * @param updatedBlob The updated blob.
	 * @param addr The address of the blob to update.
	 * @param program The program that will get the update.
	 */
	public boolean updateBlob(CliBlob updatedBlob, Address addr, Program program) {

		// Get and validate the containing structure at the given address
		Data containingData = program.getListing().getDefinedDataContaining(addr);
		if (containingData == null || !containingData.isStructure()) {
			Msg.error(this, "Containing data of " + updatedBlob.getName() + " at address " + addr +
				" is not a structure.");
			return false;
		}
		Structure containingStructure = (Structure) containingData.getDataType();

		// Make sure there is an old blob at the given address
		int structureOffset = (int) addr.subtract(containingData.getAddress());
		DataTypeComponent oldBlobDataComponent =
			containingStructure.getComponentAt(structureOffset);
		if (oldBlobDataComponent == null) {
			Msg.error(this, "Existing blob at address " + addr + " was not found.");
			return false;
		}

		// Make sure the old blob has the same size as the new blob
		DataType oldBlobDataType = oldBlobDataComponent.getDataType();
		DataType newBlobDataType = updatedBlob.toDataType();
		if (oldBlobDataType.getLength() != newBlobDataType.getLength()) {
			Msg.error(this,
				"Cannot replace existing blob at address " + addr + " with " +
					updatedBlob.getName() + " because they have different sizes (Old: " +
					oldBlobDataType.getLength() + ", New: " + newBlobDataType.getLength() + ").");
			return false;
		}

		// Update the blob
		containingStructure.replaceAtOffset(structureOffset, newBlobDataType, updatedBlob.getSize(),
			updatedBlob.getName(), updatedBlob.getContentsComment());

		return true;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(new CategoryPath(PATH), header.getName(), 0);
		struct.add(BYTE, "Reserved", "Always 0");
		for (Map.Entry<Integer, CliBlob> entry : blobMap.entrySet()) {
			int index = entry.getKey();
			CliBlob blob = entry.getValue();
			struct.add(blob.toDataType(), blob.getSize(), "[" + Integer.toHexString(index) + "]",
				null);
		}
		return struct;
	}
}
