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
package ghidra.util.table;

import java.awt.Component;
import java.awt.GridLayout;
import java.util.List;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.util.Msg;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.field.CodeUnitTableCellData;

/**
 * Renderer for {@link CodeUnitTableCellData}s
 */
public class CodeUnitTableCellRenderer extends AbstractGColumnRenderer<CodeUnitTableCellData> {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JComponent component = (JComponent) super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		if (value == null) {
			return component;
		}

		// this class is only meant to handle CodeUnitTableCellData objects
		if (!(value instanceof CodeUnitTableCellData)) {
			Msg.error(this,
				"Renderer is not being used on " + CodeUnitTableCellData.class.getSimpleName());
			return component;
		}

		CodeUnitTableCellData cuData = (CodeUnitTableCellData) value;
		List<String> displayStrings = cuData.getDisplayStrings();
		String tooltipText = cuData.getHTMLDisplayString();

		if (displayStrings.size() > 1) {
			component = getMultiLineRenderer(displayStrings);
		}
		else {
			component =
				getSingleLineRenderer(displayStrings.isEmpty() ? "" : displayStrings.get(0));
		}

		component.setToolTipText(tooltipText);

		return component;
	}

	private JComponent getSingleLineRenderer(String displayText) {
		setText(displayText);
		setFont(getFixedWidthFont());
		return this;
	}

	private JComponent getMultiLineRenderer(List<String> displayStrings) {
		JPanel panel = new JPanel(new GridLayout(displayStrings.size(), 1));
		panel.setOpaque(true);
		panel.setBackground(getBackground());
		panel.setBorder(getBorder());

		for (String string : displayStrings) {
			JLabel label = new GDLabel();

			// configure the renderer for display--these settings were taken from the 
			// GhidraTableCellRenderer, so if that changes, then this will need to change :(
			label.setBackground(getBackground());
			label.setHorizontalAlignment(getHorizontalAlignment());
			label.setOpaque(isOpaque());
			label.setBorder(getNoFocusBorder());

			label.setFont(getFixedWidthFont());
			label.setText(string);
			panel.add(label);
		}
		return panel;
	}

	@Override
	public String getFilterString(CodeUnitTableCellData t, Settings settings) {
		if (t == null) {
			return "";
		}
		return t.getDisplayString();
	}
}
