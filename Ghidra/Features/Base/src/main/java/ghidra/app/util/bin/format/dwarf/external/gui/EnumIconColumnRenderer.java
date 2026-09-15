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
package ghidra.app.util.bin.format.dwarf.external.gui;

import java.awt.Component;

import javax.swing.*;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

/**
 * Table column renderer to render an enum value as a icon
 * 
 * @param <E> enum type
 */
public class EnumIconColumnRenderer<E extends Enum<E>>
		extends AbstractGColumnRenderer<E> {

	private Icon[] icons;
	private String[] toolTips;

	EnumIconColumnRenderer(Class<E> enumClass, Icon[] icons, String[] toolTips) {
		if (enumClass.getEnumConstants().length != icons.length ||
			icons.length != toolTips.length) {
			throw new IllegalArgumentException();
		}
		this.icons = icons;
		this.toolTips = toolTips;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		E e = (E) data.getValue();
		renderer.setHorizontalAlignment(SwingConstants.CENTER);
		renderer.setText("");
		renderer.setIcon(e != null ? icons[e.ordinal()] : null);
		renderer.setToolTipText(e != null ? toolTips[e.ordinal()] : null);
		return renderer;
	}

	@Override
	protected String getText(Object value) {
		return "";
	}

	@Override
	public String getFilterString(E t, Settings settings) {
		return t == null ? "" : t.toString();
	}

}
