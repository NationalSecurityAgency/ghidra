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
package ghidra.app.plugin.exceptionhandlers.gcc.datatype;

import ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecoderFactory;
import ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * A data type whose value is a particular Dwarf decoder.
 */
public class DwarfEncodingModeDataType extends BuiltIn {

	public final static DwarfEncodingModeDataType dataType = new DwarfEncodingModeDataType();

	/**
	 * Data type whose value indicates the type of Dwarf encoding used for other data.
	 */
	public DwarfEncodingModeDataType() {
		this(null);
	}

	/**
	 * Data type whose value indicates the type of Dwarf encoding used for other data.
	 * @param dtm the data type manager associated with this data type.
	 */
	public DwarfEncodingModeDataType(DataTypeManager dtm) {
		super(CategoryPath.ROOT, "dwfenc", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new DwarfEncodingModeDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "dwfenc";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getDescription() {
		return "DWARF value-encoding mode";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		int mode = -1;
		try {
			mode = buf.getByte(0) & 0xFF;
		}
		catch (MemoryAccessException mae) {
			return null;
		}
		return DwarfDecoderFactory.getDecoder(mode);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		final int size = 1;
		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return "??";
		}

		DwarfEHDecoder decoder = DwarfDecoderFactory.getDecoder(bytes[0]);

		return decoder.toString();
	}
}
