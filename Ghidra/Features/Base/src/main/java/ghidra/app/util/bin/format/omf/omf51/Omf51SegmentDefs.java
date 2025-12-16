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
package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf51SegmentDefs extends OmfRecord {

	private boolean largeSegmentId;
	private List<Omf51Segment> segments = new ArrayList<>();
	
	/**
	 * Creates a new {@link Omf51SegmentDefs} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param largeSegmentId True if the segment ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51SegmentDefs(BinaryReader reader, boolean largeSegmentId) throws IOException {
		super(reader);
		this.largeSegmentId = largeSegmentId;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			segments.add(new Omf51Segment(dataReader, largeSegmentId));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (Omf51Segment segment : segments) {
			struct.add(largeSegmentId ? WORD : BYTE, "id", null);
			struct.add(BYTE, "info", null);
			struct.add(BYTE, "rel type", null);
			struct.add(BYTE, "unused", null);
			struct.add(WORD, "base", null);
			struct.add(WORD, "size", null);
			struct.add(segment.name().toDataType(), segment.name().getDataTypeSize(), "name", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * {@return the list of segments}
	 */
	public List<Omf51Segment> getSegments() {
		return segments;
	}
}
