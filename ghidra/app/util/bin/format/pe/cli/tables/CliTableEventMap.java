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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;

/**
 * Describes the EventMap table. Each row is an event list for a class.
 */
public class CliTableEventMap extends CliAbstractTable {
	public class CliEventMapRow extends CliAbstractTableRow {
		public int parentIndex;
		public int eventIndex;
		
		public CliEventMapRow(int parentIndex, int eventIndex) {
			super();
			this.parentIndex = parentIndex;
			this.eventIndex = eventIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format("Parent %s EventList %s", getRowRepresentationSafe(CliTypeTable.TypeDef, parentIndex), getRowRepresentationSafe(CliTypeTable.Event, eventIndex));
		}
	}
	
	public CliTableEventMap(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliEventMapRow(readTableIndex(reader, CliTypeTable.TypeDef), readTableIndex(reader, CliTypeTable.Event)));
		}
	}
	
	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "EventMap Row", 0);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.TypeDef), "Parent", null);
		rowDt.add(metadataStream.getTableIndexDataType(CliTypeTable.Event), "EventList", "First of a contiguous run in Event table, ending with next EventMap reference or end of table.");
		return rowDt;
	}
}
