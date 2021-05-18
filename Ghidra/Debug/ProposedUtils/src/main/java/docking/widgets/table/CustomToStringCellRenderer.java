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
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.BiFunction;

import javax.swing.*;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.table.TableModel;
import javax.swing.text.View;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class CustomToStringCellRenderer<T> extends AbstractGColumnRenderer<T> {

	public enum CustomFont {
		DEFAULT, MONOSPACED, BOLD;
	}

	public static String longToPrefixedHexString(long v) {
		return v < 0 ? "-0x" + Long.toString(-v, 16) : "0x" + Long.toString(v, 16);
	}

	public static String bigIntToPrefixedHexString(BigInteger v) {
		return v.signum() < 0 ? "-0x" + v.negate().toString(16) : "0x" + v.toString(16);
	}

	public static final DateFormat TIME_FORMAT_24HMSms = new SimpleDateFormat("HH:mm:ss.SSS");

	public static final CustomToStringCellRenderer<Date> TIME_24HMSms =
		new CustomToStringCellRenderer<>(CustomFont.DEFAULT, Date.class,
			(v, s) -> v == null ? "<null>" : TIME_FORMAT_24HMSms.format(v), false);
	public static final CustomToStringCellRenderer<String> HTML =
		new CustomToStringCellRenderer<String>(CustomFont.DEFAULT, String.class,
			(v, s) -> v == null ? "<null>" : v, true);
	public static final CustomToStringCellRenderer<Object> MONO_OBJECT =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Object.class,
			(v, s) -> v == null ? "<null>" : v.toString(), false);
	public static final CustomToStringCellRenderer<String> MONO_HTML =
		new CustomToStringCellRenderer<String>(CustomFont.MONOSPACED, String.class,
			(v, s) -> v == null ? "<null>" : v, true);
	public static final CustomToStringCellRenderer<Long> MONO_LONG_HEX =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Long.class,
			(v, s) -> v == null ? "<null>" : longToPrefixedHexString(v), false);
	public static final CustomToStringCellRenderer<Long> MONO_ULONG_HEX =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, Long.class,
			(v, s) -> v == null ? "<null>" : "0x" + Long.toUnsignedString(v, 16), false);
	public static final CustomToStringCellRenderer<BigInteger> MONO_BIG_HEX =
		new CustomToStringCellRenderer<>(CustomFont.MONOSPACED, BigInteger.class,
			(v, s) -> v == null ? "<null>" : bigIntToPrefixedHexString(v), false);

	private final CustomFont customFont;
	private final Class<T> cls;
	private final BiFunction<T, Settings, String> toString;

	private final JPanel panelForSize = new JPanel();
	private final BoxLayout layoutForSize = new BoxLayout(panelForSize, BoxLayout.Y_AXIS);

	public CustomToStringCellRenderer(Class<T> cls, BiFunction<T, Settings, String> toString,
			boolean enableHtml) {
		this(null, cls, toString, enableHtml);
	}

	public CustomToStringCellRenderer(CustomFont font, Class<T> cls,
			BiFunction<T, Settings, String> toString, boolean enableHtml) {
		this.setHTMLRenderingEnabled(enableHtml);
		this.customFont = font;
		this.cls = cls;
		this.toString = toString;

		panelForSize.setLayout(layoutForSize);
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
		if (getHTMLRenderingEnabled()) {
			setVerticalAlignment(SwingConstants.TOP);
		}
		else {
			setVerticalAlignment(SwingConstants.CENTER);
		}
		return this;
	}

	public int getRowHeight(int colWidth) {
		View v = (View) getClientProperty(BasicHTML.propertyKey);
		if (v == null) {
			return 0;
		}
		v.setSize(colWidth, Short.MAX_VALUE);
		return (int) v.getPreferredSpan(View.Y_AXIS);
	}
}
