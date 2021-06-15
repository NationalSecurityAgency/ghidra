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
package ghidra.app.util.bin.format.pe.rich;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pe.RichHeader;
import ghidra.app.util.bin.format.pe.RichTable;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.StringUtilities;

public class PERichTableDataType extends DynamicDataType {

	public PERichTableDataType() {
		this(null);
	}

	public PERichTableDataType(DataTypeManager dtm) {
		super(CategoryPath.ROOT, RichHeader.NAME, dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PERichTableDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return RichHeader.NAME;
	}

	@Override
	public String getDescription() {
		return RichHeader.NAME;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return new RichTable(buf);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	protected final synchronized int addComp(DataType dataType, int length, String fieldName,
			List<DataTypeComponent> comps, int offset, String comment) {
		comps.add(new ReadOnlyDataTypeComponent(dataType, this, length, comps.size(), offset,
			fieldName, comment));
		return offset + length;
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {

		final RichTable table = new RichTable(buf);

		List<DataTypeComponent> comps = new ArrayList<>();

		PERichXorDataType xor = new PERichXorDataType(table.getMask());

		int offset = 0;
		offset = addComp(new PERichDanSDataType(table.getMask()), 4, "", comps, offset, null);
		offset = addComp(xor, 4, "__pad0", comps, offset, null);
		offset = addComp(xor, 4, "__pad1", comps, offset, null);
		offset = addComp(xor, 4, "__pad2", comps, offset, null);

		RichHeaderRecord[] records = table.getRecords();

		int productFieldNameWidth = 1;
		{
			int numRecs = records.length;
			while (numRecs > 10) {
				productFieldNameWidth++;
				numRecs /= 10;
			}
		}

		for (int i = 0; i < records.length; i++) {
			RichHeaderRecord record = records[i];
			RichTableRecordDataType recType = new RichTableRecordDataType(record);

			String fieldName = String.format("product_%0" + productFieldNameWidth + "d", i);

			String comment = String.format("%s; %d %s", record.getCompId().toString(),
				record.getObjectCount(), record.getObjectCount() == 1 ? "Object" : "Objects");

			offset = addComp(recType, 8, fieldName, comps, offset, comment);
		}

		offset = addComp(new PERichSignatureDataType(), 4, "signature", comps, offset, null);
		offset = addComp(DWordDataType.dataType, 4, "mask", comps, offset, null);

		return comps.toArray(new DataTypeComponent[comps.size()]);
	}

	private class PERichDanSDataType extends BuiltIn {
		private final int mask;

		public PERichDanSDataType(int mask) {
			this(null, mask);
		}

		public PERichDanSDataType(DataTypeManager dtm, int mask) {
			super(new CategoryPath("/PE"), "DanS Field", dtm);
			this.mask = mask;
		}

		@Override
		public boolean hasLanguageDependantLength() {
			return false;
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			if (dtm == getDataTypeManager()) {
				return this;
			}
			return new PERichDanSDataType(dtm, mask);
		}

		@Override
		public String getMnemonic(Settings settings) {
			return "";
		}

		@Override
		public int getLength() {
			return 4;
		}

		@Override
		public String getDescription() {
			return "";
		}

		@Override
		public Object getValue(MemBuffer buf, Settings settings, int length) {
			try {
				return buf.getInt(0) ^ mask;
			}
			catch (MemoryAccessException mae) {
				return 0;
			}
		}

		@Override
		public String getRepresentation(MemBuffer buf, Settings settings, int length) {

			Integer value = (Integer) getValue(buf, settings, length);

			byte[] bytes = new byte[4];
			bytes[3] = (byte) ((value >> 24) & 0xFF);
			bytes[2] = (byte) ((value >> 16) & 0xFF);
			bytes[1] = (byte) ((value >> 8) & 0xFF);
			bytes[0] = (byte) ((value) & 0xFF);

			return StringUtilities.toQuotedString(bytes, 1);

		}
	}

	private class PERichSignatureDataType extends BuiltIn {

		public PERichSignatureDataType() {
			this(null);
		}

		public PERichSignatureDataType(DataTypeManager dtm) {
			super(new CategoryPath("/PE"), "Signature Field", dtm);

		}

		@Override
		public boolean hasLanguageDependantLength() {
			return false;
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			if (dtm == getDataTypeManager()) {
				return this;
			}
			return new PERichSignatureDataType(dtm);
		}

		@Override
		public String getMnemonic(Settings settings) {
			return "";
		}

		@Override
		public int getLength() {
			return 4;
		}

		@Override
		public String getDescription() {
			return "";
		}

		@Override
		public Object getValue(MemBuffer buf, Settings settings, int length) {
			try {
				return buf.getInt(0);
			}
			catch (MemoryAccessException mae) {
				return 0;
			}
		}

		@Override
		public String getRepresentation(MemBuffer buf, Settings settings, int length) {

			Integer value = (Integer) getValue(buf, settings, length);

			byte[] bytes = new byte[4];
			bytes[3] = (byte) ((value >> 24) & 0xFF);
			bytes[2] = (byte) ((value >> 16) & 0xFF);
			bytes[1] = (byte) ((value >> 8) & 0xFF);
			bytes[0] = (byte) ((value) & 0xFF);

			return StringUtilities.toQuotedString(bytes, 1);
		}
	}

	private class PERichXorDataType extends BuiltIn {

		private final int mask;

		public PERichXorDataType(int mask) {
			this(null, mask);
		}

		public PERichXorDataType(DataTypeManager dtm, int mask) {
			super(new CategoryPath("/PE"), "XOR Field", dtm);
			this.mask = mask;
		}

		@Override
		public boolean hasLanguageDependantLength() {
			return false;
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			if (dtm == getDataTypeManager()) {
				return this;
			}
			return new PERichXorDataType(dtm, mask);
		}

		@Override
		public String getMnemonic(Settings settings) {
			return "xorddw";
		}

		@Override
		public int getLength() {
			return 4;
		}

		@Override
		public String getDescription() {
			return "";
		}

		@Override
		public Object getValue(MemBuffer buf, Settings settings, int length) {
			try {
				return buf.getInt(0) ^ mask;
			}
			catch (MemoryAccessException mae) {
				return 0;
			}
		}

		@Override
		public String getRepresentation(MemBuffer buf, Settings settings, int length) {
			try {
				return new Integer(buf.getInt(0) ^ mask).toString();
			}
			catch (MemoryAccessException mae) {
				return "0";
			}
		}

	}

}
