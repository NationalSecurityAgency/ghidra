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

	// arbitrary limit to keep the table from reading too many bytes and becoming sluggish
	private static final int BYTE_LIMIT = 20;

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
	public Byte[] getValue(Address rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		try {

			int offset = MEMORY_OFFSET.getOffset(settings);
			int byteCount = BYTE_COUNT.getChoice(settings);

			Address addr = rowObject;
			if (offset != 0) {
				addr = addr.add(offset);
				if (byteCount == 0) {
					// note: would be nice to know why we only read one byte when there is an offset
					byteCount = 1;
				}
			}

			if (byteCount == 0) {
				return getBytesFromCodeUnit(program, addr);
			}

			// read bytes; one of: 1, 2, 3, 4, 5, 6, 7, 8
			byte[] bytes = new byte[byteCount];
			program.getMemory().getBytes(addr, bytes);

			return toBigBytes(bytes);
		}
		catch (MemoryAccessException e) {
			// handled below
		}
		catch (AddressOutOfBoundsException e) {
			// handled below
		}

		return new Byte[0];
	}

	private Byte[] getBytesFromCodeUnit(Program p, Address addr) throws MemoryAccessException {

		Listing listing = p.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu == null) { // can happen for 'SpecialAddress'es
			return new Byte[0];
		}

		byte[] bytes;
		int n = Math.min(cu.getLength(), BYTE_LIMIT);
		if (cu instanceof Instruction instr) {
			bytes = instr.getParsedBytes();
		}
		else {
			bytes = new byte[n];
			cu.getBytes(bytes, 0);
		}

		return toBigBytes(bytes);
	}

	private Byte[] toBigBytes(byte[] b) {

		Byte[] bigBytes = new Byte[b.length];
		for (int i = 0; i < b.length; i++) {
			bigBytes[i] = Byte.valueOf(b[i]);
		}
		return bigBytes;
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
