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
package ghidra.app.plugin.core.debug.gui.console;

import java.awt.*;
import java.text.NumberFormat;

import javax.swing.*;
import javax.swing.border.Border;

import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.debug.api.progress.MonitorReceiver;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

public class MonitorCellRenderer extends JPanel
		implements GColumnRenderer<MonitorReceiver> {
	static final MonitorCellRenderer INSTANCE = new MonitorCellRenderer();

	private static final Color BACKGROUND_COLOR = new GColor("color.bg.table.row");
	private static final Color ALT_BACKGROUND_COLOR = new GColor("color.bg.table.row.alt");
	private static final String DISABLE_ALTERNATING_ROW_COLORS_PROPERTY =
		"disable.alternating.row.colors";

	private static boolean getAlternateRowColors() {
		return !Boolean.getBoolean(DISABLE_ALTERNATING_ROW_COLORS_PROPERTY);
	}

	static class CachedColor {
		Color cached;

		Color copy(Color c) {
			if (cached == null || cached.getRGB() != c.getRGB()) {
				cached = new Color(c.getRGB());
			}
			return cached;
		}
	}

	protected CachedColor selFg = new CachedColor();
	protected CachedColor selBg = new CachedColor();

	protected final Border focusBorder;
	protected final Border noFocusBorder;
	protected final JProgressBar bar = new JProgressBar();
	protected final JLabel label = new JLabel();

	public MonitorCellRenderer() {
		super(new BorderLayout());
		noFocusBorder = BorderFactory.createEmptyBorder(1, 5, 1, 5);
		Border innerBorder = BorderFactory.createEmptyBorder(0, 4, 0, 4);
		Border outerBorder = BorderFactory.createLineBorder(Palette.YELLOW, 1);
		focusBorder = BorderFactory.createCompoundBorder(outerBorder, innerBorder);

		add(bar);
		add(label, BorderLayout.SOUTH);
	}

	protected Color getAlternatingBackgroundColor(int row) {
		if (!getAlternateRowColors() || (row & 1) == 1) {
			return BACKGROUND_COLOR;
		}
		return ALT_BACKGROUND_COLOR;
	}

	@Override
	public final Component getTableCellRendererComponent(JTable table, Object value,
			boolean isSelected, boolean hasFocus, int row, int column) {
		setOpaque(true);
		if (isSelected) {
			setForeground(selFg.copy(table.getSelectionForeground()));
			label.setForeground(selFg.copy(table.getSelectionForeground()));
			setBackground(selBg.copy(table.getSelectionBackground()));
		}
		else {
			setForeground(table.getForeground());
			label.setForeground(table.getForeground());
			setBackground(getAlternatingBackgroundColor(row));
		}
		setBorder(hasFocus ? focusBorder : noFocusBorder);

		if (!(value instanceof MonitorReceiver monitor)) {
			return this;
		}

		if (monitor.isCancelled()) {
			label.setText("(cancelled) " + monitor.getMessage());
		}
		else {
			label.setText(monitor.getMessage());
		}

		StringBuilder sb = new StringBuilder();
		long progress = monitor.getProgress();
		long maximum = monitor.getMaximum();
		if (progress != TaskMonitor.NO_PROGRESS_VALUE) {
			if (progress <= 0) {
				sb.append("0%");
			}
			else if (progress >= maximum) {
				sb.append("100%");
			}
			else {
				sb.append(NumberFormat.getPercentInstance().format((float) progress / maximum));
			}
			if (monitor.isShowProgressValue()) {
				sb.append(" (");
				sb.append(progress);
				sb.append(" of ");
				sb.append(maximum);
				sb.append(")");
			}
		}
		bar.setString(sb.toString());
		bar.setStringPainted(true);
		BoundedRangeModel model = bar.getModel();
		try {
			model.setValueIsAdjusting(true);
			model.setMaximum(Integer.MAX_VALUE);
			if (progress == TaskMonitor.NO_PROGRESS_VALUE) {
				bar.setIndeterminate(true);
				model.setValue(0);
			}
			else {
				bar.setIndeterminate(monitor.isIndeterminate());
				double val = Integer.MAX_VALUE;
				val *= progress;
				val /= maximum;
				model.setValue((int) val);
			}
		}
		finally {
			model.setValueIsAdjusting(false);
		}
		return this;
	}

	@Override
	public String getFilterString(MonitorReceiver t, Settings settings) {
		return t.getMessage();
	}
}
