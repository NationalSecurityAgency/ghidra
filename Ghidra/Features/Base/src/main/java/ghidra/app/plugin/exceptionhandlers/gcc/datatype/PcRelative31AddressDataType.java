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

import ghidra.docking.settings.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * An Address datatype whose value is computed in relation to its location in memory.
 */
public class PcRelative31AddressDataType extends BuiltIn {

	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF;
	private static final PaddingSettingsDefinition PADDING = PaddingSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS = { FORMAT, PADDING };

	public final static PcRelative31AddressDataType dataType = new PcRelative31AddressDataType();

	/**
	 * Creates a PC relative address data type using the bottom 31 bits.
	 */
	public PcRelative31AddressDataType() {
		this(null);
	}

	/**
	 * Creates a PC relative address data type using the bottom 31 bits.
	 * @param dtm the data type manager associated with this data type.
	 */
	public PcRelative31AddressDataType(DataTypeManager dtm) {
		super(null, "prel31", dtm);
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new PcRelative31AddressDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getDescription() {
		return "PC-Relative address using bottom 31 bits";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			int ptr = buf.getInt(0) & 0xFFFFFFFF;
			ptr |= 0x80000000;
			int offset = (ptr << 1) >> 1;
			return buf.getAddress().add(offset);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException mae) {
			return null;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Address addr = (Address) getValue(buf, settings, length);
		if (addr == null) {
			return "??";
		}
		return addr.toString();

	}

}
