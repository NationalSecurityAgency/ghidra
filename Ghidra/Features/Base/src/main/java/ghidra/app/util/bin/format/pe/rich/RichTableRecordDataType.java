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

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;

class RichTableRecordDataType extends StructureDataType {

	private final RichHeaderRecord record;

	public RichTableRecordDataType(RichHeaderRecord record) {
		this(null, record);
	}

	public RichTableRecordDataType(DataTypeManager dtm, RichHeaderRecord record) {
		super(new CategoryPath("/PE"), "MSRichRecord", 0, dtm);
		this.record = record;

		initialize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return false;
	}

	@Override
	public RichTableRecordDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RichTableRecordDataType(dtm, record);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "MSRichRecord";
	}

	@Override
	public int getLength() {
		return 8;
	}

	@Override
	public String getDescription() {
		return "MS Rich Table Record";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return record;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "";
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	private void initialize() {
		add(new MSRichProductInfoDataType(record.getCompId()), 4, "productInfo", null);
		add(new RichObjectCountDataType(record.getObjectCount()), 4, "objectCount", null);
	}

}
