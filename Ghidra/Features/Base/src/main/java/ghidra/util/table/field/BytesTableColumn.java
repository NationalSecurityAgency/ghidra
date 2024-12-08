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
package ghidra.util.table.field;

import ghidra.docking.settings.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.BytesFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table field displays the bytes for the code unit beginning at the address
 * associated with a row in the table.
 */
public class BytesTableColumn extends ProgramLocationTableColumnExtensionPoint<Address, Byte[]> {

	private static final ByteCountSettingsDefinition BYTE_COUNT = ByteCountSettingsDefinition.DEF;
	private static final MemoryOffsetSettingsDefinition MEMORY_OFFSET =
		MemoryOffsetSettingsDefinition.DEF;
	private static final EndianSettingsDefinition ENDIANNESS = EndianSettingsDefinition.DEF;
	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS =
		{ BYTE_COUNT, MEMORY_OFFSET, ENDIANNESS, FORMAT };

	private final GColumnRenderer<Byte[]> monospacedRenderer = new MonospacedByteRenderer();

	/**
	 * Default Constructor
	 */
	public BytesTableColumn() {
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		String name = getColumnName();
		int byteCnt = BYTE_COUNT.getChoice(settings);
		if (byteCnt != 0) {
			name += "[" + byteCnt + "]";
		}
		String offset = MEMORY_OFFSET.getDisplayValue(settings);
		if (!"0".equals(offset)) {
			name += offset;
		}
		return name;
	}

	@Override
	public String getColumnName() {
		return "Bytes";
	}

	@Override
	public Byte[] getValue(Address rowObject, Settings settings, Program pgm,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		Address addr = rowObject;
		try {

			int offset = MEMORY_OFFSET.getOffset(settings);
			int byteCnt = BYTE_COUNT.getChoice(settings);
			byte[] bytes = null;

			if (offset != 0) {
				addr = addr.add(offset);
			}

			if (byteCnt == 0) {
				if (offset != 0) {
					byteCnt = 1;
				}
				else {
					CodeUnit cu = pgm.getListing().getCodeUnitContaining(addr);
					if (cu == null) { // can happen for 'SpecialAddress'es
						return new Byte[0];
					}
					if (cu instanceof Instruction instr) {
						bytes = instr.getParsedBytes();
					}
					else {
						bytes = cu.getBytes();
					}
				}
			}

			if (bytes == null) {
				bytes = new byte[byteCnt];
				pgm.getMemory().getBytes(addr, bytes);
			}

			Byte[] bytesObj = new Byte[bytes.length];
			for (int i = 0; i < bytes.length; i++) {
				bytesObj[i] = Byte.valueOf(bytes[i]);
			}

			return bytesObj;

		}
		catch (MemoryAccessException e) {
			// handled below
		}
		catch (AddressOutOfBoundsException e) {
			// handled below
		}

		return new Byte[0];
	}

	@Override
	public GColumnRenderer<Byte[]> getColumnRenderer() {
		return monospacedRenderer;
	}

	@Override
	public ProgramLocation getProgramLocation(Address rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) {
		Address address = rowObject;

		int offset = MEMORY_OFFSET.getOffset(settings);
		if (offset != 0) {
			try {
				address = address.addNoWrap(offset);
			}
			catch (AddressOverflowException e) {
				// handled below
			}
		}
		return new BytesFieldLocation(program, address);
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return SETTINGS_DEFS;
	}
}
