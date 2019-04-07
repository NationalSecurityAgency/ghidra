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

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.BytesFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.StringFormat;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table field displays the bytes for the code unit beginning at the address
 * associated with a row in the table.
 */
public class BytesTableColumn extends ProgramLocationTableColumnExtensionPoint<Address, Byte[]> {

	private static final ByteCountSettingsDefinition BYTE_COUNT = ByteCountSettingsDefinition.DEF;
	private static final MemoryOffsetSettingsDefinition MEMORY_OFFSET =
		MemoryOffsetSettingsDefinition.DEF;
	private static final EndianSettingsDefinition ENDIANESS = EndianSettingsDefinition.DEF;
	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF;

	private static SettingsDefinition[] SETTINGS_DEFS =
		{ BYTE_COUNT, MEMORY_OFFSET, ENDIANESS, FORMAT };

	private final GColumnRenderer<Byte[]> monospacedRenderer =
		new AbstractGColumnRenderer<Byte[]>() {
			@Override
			protected void configureFont(JTable table, TableModel model, int column) {
				setFont(getFixedWidthFont());
			}

			private String formatBytes(Byte[] bytes, Settings settings) {
				boolean bigEndian =
					(ENDIANESS.getChoice(settings) != EndianSettingsDefinition.LITTLE);

				int startIx = 0;
				int endIx = bytes.length;
				int inc = 1;
				if (!bigEndian) {
					startIx = bytes.length - 1;
					endIx = -1;
					inc = -1;
				}

				int format = FORMAT.getChoice(settings);
				if (format == FormatSettingsDefinition.CHAR) {
					return bytesToString(bytes);
				}

				StringBuffer buffer = new StringBuffer();
				for (int i = startIx; i != endIx; i += inc) {
					if (buffer.length() != 0) {
						buffer.append(' ');
					}
					buffer.append(getByteString(bytes[i], format));
				}
				return buffer.toString();
			}

			private String bytesToString(Byte[] bytes) {
				StringBuffer buf = new StringBuffer();
				for (byte b : bytes) {
					char c = (char) (b & 0xff);
					if (c > 32 && c < 128) {
						buf.append((char) (b & 0xff));
					}
					else {
						buf.append('.');
					}
				}
				return buf.toString();
			}

			private String getByteString(Byte b, int format) {

				String val;
				switch (format) {
					case FormatSettingsDefinition.DECIMAL:
						val = Integer.toString(b);
						break;
					case FormatSettingsDefinition.BINARY:
						val = Integer.toBinaryString(b & 0x0ff);
						val = StringFormat.padIt(val, 8, (char) 0, true);
						break;
					case FormatSettingsDefinition.OCTAL:
						val = Integer.toOctalString(b & 0x0ff);
						val = StringFormat.padIt(val, 3, (char) 0, true);
						break;
					default:
					case FormatSettingsDefinition.HEX:
						val = Integer.toHexString(b & 0x0ff).toUpperCase();
						val = StringFormat.padIt(val, 2, (char) 0, true);
						break;
				}
				return val;
			}

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				Object value = data.getValue();
				Settings settings = data.getColumnSettings();

				Byte[] bytes = (Byte[]) value;

				setText(formatBytes(bytes, settings));

				return label;
			}

			@Override
			public String getFilterString(Byte[] t, Settings settings) {
				String formatted = formatBytes(t, settings);
				return formatted;
			}
		};

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
					bytes = cu.getBytes();
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
