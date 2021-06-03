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
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.DataConverter;
import ghidra.util.classfinder.ClassTranslator;

/**
 * Provides a definition of a Double Word within a program.
 */
public class ShiftedAddressDataType extends BuiltIn {
	static {
		ClassTranslator.put("ghidra.program.model.data.Addr32shft",
			ShiftedAddressDataType.class.getName());
		ClassTranslator.put("ghidra.program.model.data.Addr32shftDataType",
			ShiftedAddressDataType.class.getName());
	}

	public final static ShiftedAddressDataType dataType = new ShiftedAddressDataType();

	private static SettingsDefinition[] SETTINGS_DEFS = {};

	/**
	 * Creates a Double Word data type.
	 */
	public ShiftedAddressDataType() {
		this(null);
	}

	public ShiftedAddressDataType(DataTypeManager dtm) {
		super(null, "ShiftedAddress", dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "addr";
	}

	@Override
	public int getLength() {
		return getDataOrganization().getPointerSize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public String getDescription() {
		return "shifted address (as specified by compiler spec)";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		DataOrganization dataOrg = getDataOrganization();
		return getAddressValue(buf, dataOrg.getPointerSize(), dataOrg.getPointerShift(),
			buf.getAddress().getAddressSpace());
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	/**
	 * Generate an address value based upon bytes stored at the specified buf location
	 * @param buf memory buffer and stored pointer location
	 * @param size pointer size in bytes
	 * @param shift left shift amount
	 * @param targetSpace address space for returned pointer
	 * @return pointer value or null if unusable buf or data
	 */
	public static Address getAddressValue(MemBuffer buf, int size, int shift,
			AddressSpace targetSpace) {

		if (size <= 0 || size > 8) {
			return null;
		}

		if (buf.getAddress() instanceof SegmentedAddress) {
			// not supported for segmented addresses
			return null;
		}

		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return null;
		}

		long val = DataConverter.getInstance(buf.isBigEndian()).getValue(bytes, size);

		val = val << shift;

		try {
			return targetSpace.getAddress(val, true);
		}
		catch (AddressOutOfBoundsException e) {
			// offset too large
		}
		catch (IllegalArgumentException iae) {
			// Do nothing... Tried to create an address that was too large
			// for the address space
			//
			// For example, trying to create a 56 bit pointer in a
			// 32 bit address space.
		}
		return null;
	}

	protected String getString(MemBuffer buf, Settings settings) {
		Address addr = (Address) getValue(buf, settings, getLength());
		if (addr != null) {
			return addr.toString();
		}
		return "??";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getString(buf, settings);
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
		return new ShiftedAddressDataType(dtm);
	}

}
