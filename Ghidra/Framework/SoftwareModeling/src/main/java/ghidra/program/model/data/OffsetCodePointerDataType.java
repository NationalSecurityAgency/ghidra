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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ClassTranslator;

public class OffsetCodePointerDataType extends BuiltIn {
	static {
		ClassTranslator.put("ghidra.program.model.data.OffsetCodePointer",
			OffsetCodePointerDataType.class.getName());
	}

	public static OffsetCodePointerDataType dataType = new OffsetCodePointerDataType();
	
	public OffsetCodePointerDataType() {
		this(null);
	}

	public OffsetCodePointerDataType(DataTypeManager dtm) {
		super(null, "OffsetCodeAddress", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new OffsetCodePointerDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "_offsetAddr";
	}

	@Override
	public int getLength() {
		return 2;
	}

	@Override
	public String getDescription() {
		return "16 bit offset address";
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		Address addr = buf.getAddress();
		try {
			long segment = 0;
			long offset = buf.getShort(2) & 0xffff;
			long addrValue = segment << 16 | offset;
			return addr.getNewAddress(addrValue, true);
		}
		catch (AddressOutOfBoundsException | MemoryAccessException ex) {
			// Do nothing... Tried to form an address that was not readable or
			// writeable.
		}
		return null;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		Object obj = getValue(buf, settings, length);
		if (obj == null)
			return "??";
		return obj.toString();
	}

}
