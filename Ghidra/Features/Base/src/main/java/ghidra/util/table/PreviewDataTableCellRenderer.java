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

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.table.column.AbstractGColumnRenderer;

/**
 * A custom renderer used to display what is at the {@link ProgramLocation} similarly to
 * how it is displayed in the Listing window..  This class is meant to be
 * used directly with {@link PreviewTableCellData} column data.
 */
public class PreviewDataTableCellRenderer extends AbstractGColumnRenderer<PreviewTableCellData> {
	private static final Color DEFAULT_OFFCUT_FOREGROUND_COLOR = Color.RED;
	private static final Color DEFAULT_SELECTED_OFFCUT_FOREGROUND_COLOR = Color.PINK;

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		boolean isSelected = data.isSelected();

		if (value == null) {
			return renderer;
		}

		// this class is only meant to handle PreviewTableCellData objects
		if (!(value instanceof PreviewTableCellData)) {
			Msg.error(this,
				"Renderer is not being used on " + PreviewTableCellData.class.getSimpleName());
			return renderer;
		}

		PreviewTableCellData previewData = (PreviewTableCellData) value;
		String preview = previewData.getDisplayString();
		boolean isOffcut = previewData.isOffcut();
		String tooltipText = previewData.getHTMLDisplayString();

		Color foreground = getForeground(table, isSelected, isOffcut);

		renderer.setText(preview);
		renderer.setFont(getFixedWidthFont());
		renderer.setForeground(foreground);
		renderer.setToolTipText(tooltipText);

		return renderer;
	}

	private Color getForeground(JTable table, boolean isSelected, boolean isOffcut) {
		if (!isOffcut) {
			return getForeground();
		}

		// 
		// The JTable's row selection color is dark when the table has focus and a lighter gray
		// when the table does not have focus.  We want the offcut color to be light when the
		// selection is dark and we want it to be dark when the selection is light.
		//
		boolean isFocused = table.hasFocus();
		if (!isFocused) {
			return DEFAULT_OFFCUT_FOREGROUND_COLOR; // darker
		}

		return isSelected ? DEFAULT_SELECTED_OFFCUT_FOREGROUND_COLOR
				: DEFAULT_OFFCUT_FOREGROUND_COLOR;

	}

	@Override
	public String getFilterString(PreviewTableCellData t, Settings settings) {
		return t.getDisplayString();
	}
}
