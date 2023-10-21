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
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.util.StringFormat;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class MonospacedByteRenderer extends AbstractGColumnRenderer<Byte[]> {
	@Override
	protected void configureFont(JTable table, TableModel model, int column) {
		setFont(getFixedWidthFont());
	}

	private String formatBytes(Byte[] bytes, Settings settings) {
		boolean bigEndian = (EndianSettingsDefinition.DEF
				.getChoice(settings) != EndianSettingsDefinition.LITTLE);

		int startIx = 0;
		int endIx = bytes.length;
		int inc = 1;
		if (!bigEndian) {
			startIx = bytes.length - 1;
			endIx = -1;
			inc = -1;
		}

		int format = FormatSettingsDefinition.DEF.getChoice(settings);
		if (format == FormatSettingsDefinition.CHAR) {
			return bytesToString(bytes);
		}

		StringBuilder buffer = new StringBuilder();
		for (int i = startIx; i != endIx; i += inc) {
			if (buffer.length() != 0) {
				buffer.append(' ');
			}
			buffer.append(getByteString(bytes[i], format));
		}
		return buffer.toString();
	}

	private String bytesToString(Byte[] bytes) {
		StringBuilder buf = new StringBuilder();
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
}
