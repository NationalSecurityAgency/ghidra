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
package docking.widgets.table;

import java.awt.Component;
import java.awt.Font;
import java.util.function.BiFunction;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class CustomToStringCellRenderer<T> extends AbstractGColumnRenderer<T> {

	public enum CustomFont {
		DEFAULT, MONOSPACED, BOLD;
	}

	public static final CustomToStringCellRenderer<Object> MONO_OBJECT =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Object.class,
			(v, s) -> v == null ? "<null>" : v.toString());
	public static final CustomToStringCellRenderer<Long> MONO_LONG_HEX =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Long.class,
			(v, s) -> v == null ? "<null>" : "0x" + Long.toString(v, 16));
	public static final CustomToStringCellRenderer<Long> MONO_ULONG_HEX =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Long.class,
			(v, s) -> v == null ? "<null>" : "0x" + Long.toUnsignedString(v, 16));

	private final CustomFont customFont;
	private final Class<T> cls;
	private final BiFunction<T, Settings, String> toString;

	public CustomToStringCellRenderer(Class<T> cls, BiFunction<T, Settings, String> toString) {
		this(null, cls, toString);
	}

	public CustomToStringCellRenderer(CustomFont font, Class<T> cls,
			BiFunction<T, Settings, String> toString) {
		this.customFont = font;
		this.cls = cls;
		this.toString = toString;
	}

	@Override
	protected void configureFont(JTable table, TableModel model, int column) {
		setFont(getCustomFont());
	}

	protected Font getCustomFont() {
		switch (customFont) {
			default:
			case DEFAULT:
				return defaultFont;
			case MONOSPACED:
				return fixedWidthFont;
			case BOLD:
				return boldFont;
		}
	}

	// TODO: Seems the filter model does not heed this....
	@Override
	public String getFilterString(T t, Settings settings) {
		return toString.apply(t, settings);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		setText(toString.apply(cls.cast(data.getValue()), data.getColumnSettings()));
		return this;
	}
}
