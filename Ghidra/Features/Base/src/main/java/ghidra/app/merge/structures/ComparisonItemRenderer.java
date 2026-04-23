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
package ghidra.app.merge.structures;

import static javax.swing.SwingConstants.*;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import ghidra.app.merge.structures.ComparisonItemLayout.ColumnWidths;

/**
 * ListCellRenderer for rendering structure lines in {@link CoordinatedStructureDisplay}. It 
 * consists of a label for each possible column. The labels are arranged by a 
 * {@link ComparisonItemLayout} which is fed column widths for each type of line item. The 
 * columns widths for each type are computed when the renderer is constructed by examining all
 * the lines in the model and computing the min/max column widths for that type.
 */
public class ComparisonItemRenderer implements ListCellRenderer<ComparisonItem>, ListDataListener {
	private static Color FADED_COLOR = Colors.FOREGROUND_DISABLED;
	private static Color NON_FOCUSED_SELECTION_BG_COLOR =
		new GColor("color.bg.plugin.struct.merge.selection.non.focused");

	private JPanel panel;
	private JLabel[] labels = new JLabel[ComparisonItem.MAX_COLS];
	private int lineHeight;
	private ComparisonItemLayout layout;
	private Font normal;
	private Font bold;

	private FontMetrics metrics;

	private Map<String, ColumnWidths> widthsMap;

	ComparisonItemRenderer(ListModel<ComparisonItem> listModel) {
		panel = new JPanel();
		for (int i = 0; i < ComparisonItem.MAX_COLS; i++) {
			labels[i] = new JLabel();
			labels[i].setHorizontalAlignment(SwingConstants.LEFT);
			panel.add(labels[i]);
		}
		normal = labels[0].getFont();
		bold = normal.deriveFont(Font.BOLD);
		metrics = labels[0].getFontMetrics(bold);
		lineHeight = metrics.getHeight();
		layout = new ComparisonItemLayout();
		panel.setLayout(layout);
		computeColumnWidths(listModel);
		listModel.addListDataListener(this);
	}

	private void computeColumnWidths(ListModel<ComparisonItem> listModel) {
		widthsMap = new HashMap<>();
		for (int i = 0; i < listModel.getSize(); i++) {
			ComparisonItem item = listModel.getElementAt(i);
			ColumnWidths widths =
				widthsMap.computeIfAbsent(item.getType(), k -> new ColumnWidths());
			for (int col = 0; col < ComparisonItem.MAX_COLS; col++) {
				int maxWidth = metrics.stringWidth(item.getColumnText(col));
				int minWidth = item.getMinWidth(col);
				if (minWidth < 0) {
					minWidth = maxWidth;
				}
				widths.addMinWidth(col, minWidth);
				widths.addMaxWidth(col, maxWidth);
			}
		}
	}

	public FontMetrics getFontMetrics() {
		return metrics;
	}

	public int getPreferredHeight() {
		return lineHeight;
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends ComparisonItem> list,
			ComparisonItem value, int index, boolean isSelected, boolean cellHasFocus) {
		layout.setColumnWidths(widthsMap.get(value.getType()));
		boolean hasFocus = list.hasFocus();
		// Note: Setting the accessible description on the renderer works and it
		// reports the correct information as you hover or select lines in the list
		panel.getAccessibleContext().setAccessibleName(value.getType() + " line");
		panel.getAccessibleContext().setAccessibleDescription(getAccessibleDescription(value));
		Color bgColor = getBackgroundColor(list, isSelected, hasFocus);
		Color fgColor = getForegroundColor(list, isSelected, hasFocus);
		Color fadedColor = getFadedColor(fgColor, isSelected, hasFocus);
		for (int i = 0; i < ComparisonItem.MAX_COLS; i++) {
			labels[i].setText(value.getColumnText(i));
			labels[i].setHorizontalAlignment(value.isLeftJustified(i) ? LEFT : RIGHT);
			if (!value.isAppliable(i)) {
				labels[i].setFont(normal);
				labels[i].setForeground(fgColor);
			}
			else if (value.isApplied(i)) {
				labels[i].setFont(bold);
				labels[i].setForeground(fgColor);
			}
			else {
				labels[i].setFont(normal);
				labels[i].setForeground(fadedColor);
			}
		}

		panel.setBackground(bgColor);
		return panel;
	}

	private Color getBackgroundColor(JList<? extends ComparisonItem> list, boolean isSelected,
			boolean hasFocus) {
		if (!isSelected) {
			return list.getBackground();
		}
		if (hasFocus) {
			return list.getSelectionBackground();
		}
		return NON_FOCUSED_SELECTION_BG_COLOR;
	}

	private Color getForegroundColor(JList<? extends ComparisonItem> list, boolean isSelected,
			boolean hasFocus) {
		if (hasFocus && isSelected) {
			return list.getSelectionForeground();
		}
		return list.getForeground();
	}

	private String getAccessibleDescription(ComparisonItem value) {
		if (value.isBlank()) {
			return "Blank line";
		}
		StringBuilder builder = new StringBuilder();
		builder.append(value.toString());
		if (!value.isAppliable()) {
			builder.append(" Status: Not Appliable");
		}
		else if (value.canApplyAny()) {
			builder.append(" Status: Not Applied");
		}
		else {
			builder.append(" Status: Applied");
		}
		return builder.toString();
	}

	private Color getFadedColor(Color fgColor, boolean isSelected, boolean hasFocus) {
		if (isSelected && !hasFocus) {
			return fgColor;
		}
		return FADED_COLOR;
	}

	@Override
	public void intervalAdded(ListDataEvent e) {
		// don't care
	}

	@Override
	public void intervalRemoved(ListDataEvent e) {
		// don't care
	}

	@SuppressWarnings("unchecked")
	@Override
	public void contentsChanged(ListDataEvent e) {
		computeColumnWidths((ListModel<ComparisonItem>) e.getSource());
	}

}
