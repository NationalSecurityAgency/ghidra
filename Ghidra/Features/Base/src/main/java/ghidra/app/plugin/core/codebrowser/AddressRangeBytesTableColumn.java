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
package ghidra.app.plugin.core.codebrowser;

import docking.widgets.table.AbstractDynamicTableColumn;
import ghidra.docking.settings.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;

/** 
 * A column for displaying a small window of bytes around the endpoints of an {@link AddressRange}
 * in an address range table 
 */
public class AddressRangeBytesTableColumn
		extends AbstractDynamicTableColumn<AddressRangeInfo, Byte[], Program> {

	private final GColumnRenderer<Byte[]> monospacedRenderer = new MonospacedByteRenderer();
	private static SettingsDefinition[] SETTINGS =
		{ ByteCountSettingsDefinition.DEF, MemoryOffsetSettingsDefinition.DEF,
			EndianSettingsDefinition.DEF, FormatSettingsDefinition.DEF,
			AddressRangeEndpointSettingsDefinition.DEF };
	private static final String COLUMN_NAME = "Bytes";

	/**
	 * Default constructor
	 */
	public AddressRangeBytesTableColumn() {
	}

	@Override
	public String getColumnName() {
		return COLUMN_NAME;
	}

	@Override
	public Byte[] getValue(AddressRangeInfo rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		int choice = AddressRangeEndpointSettingsDefinition.DEF.getChoice(settings);
		Address base =
			choice == AddressRangeEndpointSettingsDefinition.BEGIN_CHOICE_INDEX ? rowObject.min()
					: rowObject.max();
		int offset = MemoryOffsetSettingsDefinition.DEF.getOffset(settings);
		int byteCount = ByteCountSettingsDefinition.DEF.getChoice(settings);
		byte[] bytes = null;
		//default: display the bytes in the associated CodeUnit
		//unless there is a nonzero offset.  In that case, display the one byte at that offset
		try {
			base = base.addNoWrap(offset);
			if (byteCount == ByteCountSettingsDefinition.DEFAULT) {
				if (offset != 0) {
					byteCount = 1;
				}
				else {
					CodeUnit cu = program.getListing().getCodeUnitContaining(base);
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
				bytes = new byte[byteCount];
				program.getMemory().getBytes(base, bytes);
			}

			Byte[] bytesObj = new Byte[bytes.length];
			for (int i = 0; i < bytes.length; i++) {
				bytesObj[i] = Byte.valueOf(bytes[i]);
			}
			return bytesObj;
		}
		catch (MemoryAccessException | AddressOverflowException e) {
			return new Byte[0];
		}
	}

	@Override
	public GColumnRenderer<Byte[]> getColumnRenderer() {
		return monospacedRenderer;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return SETTINGS;
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		StringBuilder sb =
			new StringBuilder(AddressRangeEndpointSettingsDefinition.DEF.getValueString(settings));
		sb.append(" ").append(COLUMN_NAME);
		int byteCnt = ByteCountSettingsDefinition.DEF.getChoice(settings);
		if (byteCnt != ByteCountSettingsDefinition.DEFAULT) {
			sb.append("[");
			sb.append(byteCnt);
			sb.append("]");
		}
		String offset = MemoryOffsetSettingsDefinition.DEF.getValueString(settings);
		if (!offset.equals("0")) {
			sb.append(offset);
		}
		return sb.toString();
	}
}
