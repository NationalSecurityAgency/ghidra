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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumEventAttributes;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexTypeDefOrRef;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.InvalidInputException;

/**
 * Describes the Event table. Each row represents an event. References to this table are to contiguous runs of events.
 * The "run" begins at the specified index and ends at the next place a reference from EventMap points, or the end of this table. 
 */
public class CliTableEvent extends CliAbstractTable {
	public class CliEventRow extends CliAbstractTableRow {
		public short eventFlags;
		public int nameIndex;
		public int eventTypeIndex;
		
		public CliEventRow(short eventFlags, int nameIndex, int eventTypeIndex) {
			super();
			this.eventFlags = eventFlags;
			this.nameIndex = nameIndex;
			this.eventTypeIndex = eventTypeIndex;
		}

		@Override
		public String getRepresentation() {
			String eventRep;
			try {
				eventRep = getRowRepresentationSafe(CliIndexTypeDefOrRef.getTableName(eventTypeIndex), CliIndexTypeDefOrRef.getRowIndex(eventTypeIndex));
			}
			catch (InvalidInputException e) {
				eventRep = Integer.toHexString(eventTypeIndex);
			}
			return String.format("%s Flags %s Type %s",
				metadataStream.getStringsStream().getString(nameIndex),
				CliEnumEventAttributes.dataType.getName(eventFlags & 0xffff), eventRep);
		}
	}
	
	public CliTableEvent(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliEventRow row = new CliEventRow(reader.readNextShort(), readStringIndex(reader), CliIndexTypeDefOrRef.readCodedIndex(reader, stream));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "Event Row", 0);
		rowDt.add(CliEnumEventAttributes.dataType, "EventFlags", null);
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", null);
		rowDt.add(CliIndexTypeDefOrRef.toDataType(metadataStream), "EventType", "type of Event, not of owning class");
		return rowDt;
	}
}
