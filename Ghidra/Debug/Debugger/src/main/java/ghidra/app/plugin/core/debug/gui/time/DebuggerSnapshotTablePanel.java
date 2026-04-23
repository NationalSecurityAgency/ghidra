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
package ghidra.app.plugin.core.debug.gui.time;

import java.awt.*;
import java.util.Date;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;

import docking.widgets.table.*;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.theme.GColor;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix;
import ghidra.util.DateUtils;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class DebuggerSnapshotTablePanel extends JPanel {
	private static final Color COLOR_FOREGROUND_STALE =
		new GColor("color.debugger.plugin.resources.register.stale");
	private static final Color COLOR_FOREGROUND_STALE_SEL =
		new GColor("color.debugger.plugin.resources.register.stale.selected");

	static final StyleCurrentSnapRenderer STYLE_CURRENT_SNAP_RENDERER =
		new StyleCurrentSnapRenderer();

	protected enum SnapshotTableColumns
		implements EnumeratedTableColumn<SnapshotTableColumns, SnapshotRow> {
		SNAP("Snap", Long.class, SnapshotRow::getSnap) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}

			@Override
			public boolean isVisible() {
				return false;
			}
		},
		TIME("Time", TraceSchedule.class, SnapshotRow::getTime) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}
		},
		EVENT_THREAD("Event Thread", String.class, SnapshotRow::getEventThreadName) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}
		},
		PC("PC", Address.class, SnapshotRow::getProgramCounter) {
			@Override
			public int getPreferredWidth() {
				return 40;
			}
		},
		MODULE("Module", String.class, SnapshotRow::getModuleName) {
			@Override
			public int getPreferredWidth() {
				return 40;
			}
		},
		FUNCTION("Function", ghidra.program.model.listing.Function.class,
				SnapshotRow::getFunction) {
			@Override
			public int getPreferredWidth() {
				return 40;
			}
		},
		TIMESTAMP("Timestamp", Date.class, SnapshotRow::getTimeStamp) {
			@Override
			public int getPreferredWidth() {
				return 200;
			}

			@Override
			public boolean isVisible() {
				return false;
			}
		},
		SCHEDULE("Schedule", TraceSchedule.class, SnapshotRow::getSchedule) {
			@Override
			public int getPreferredWidth() {
				return 60;
			}

			@Override
			public boolean isVisible() {
				return false;
			}
		},
		DESCRIPTION("Description", String.class, SnapshotRow::getDescription,
				SnapshotRow::setDescription) {
			@Override
			public int getPreferredWidth() {
				return 20;
			}
		};

		private final String header;
		private final Function<SnapshotRow, ?> getter;
		private final BiConsumer<SnapshotRow, Object> setter;
		private final Class<?> cls;

		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter) {
			this(header, cls, getter, null);
		}

		@SuppressWarnings("unchecked")
		<T> SnapshotTableColumns(String header, Class<T> cls, Function<SnapshotRow, T> getter,
				BiConsumer<SnapshotRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<SnapshotRow, Object>) setter;
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(SnapshotRow row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(SnapshotRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(SnapshotRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public GColumnRenderer<?> getRenderer() {
			return STYLE_CURRENT_SNAP_RENDERER;
		}
	}

	static class StyleCurrentSnapRenderer extends AbstractGColumnRenderer<Object>
			implements GTableAccess {

		SnapshotTableModel model;

		protected TimeRadix getTimeRadix() {
			Trace trace = model.getTrace();
			return trace == null ? TimeRadix.DEFAULT : trace.getTimeManager().getTimeRadix();
		}

		@Override
		protected String formatNumber(Number value, Settings settings) {
			return switch (value) {
				case null -> "";
				// SNAP is the only column with Long type
				case Long snap -> getTimeRadix().format(snap);
				default -> super.formatNumber(value, settings);
			};
		}

		@Override
		protected String getText(Object value) {
			return switch (value) {
				case null -> "";
				case Date date -> DateUtils.formatDateTimestamp(date);
				case TraceSchedule schedule -> schedule.toString(getTimeRadix());
				default -> value.toString();
			};
		}

		@Override
		public String getFilterString(Object t, Settings settings) {
			return switch (t) {
				case null -> "";
				// SNAP is the only column with Long type
				case Long snap -> getTimeRadix().format(snap);
				case Number n -> formatNumber(n, settings);
				default -> getText(t);
			};
		}

		Font lastFixedWidthFont;
		Font fixedWidthBoldFont;
		Font fixedWidthItalicFont;

		Font computePlainFont(GTableCellRenderingData data) {
			return data.getValue() instanceof Address ? getFixedWidthFont() : getDefaultFont();
		}

		void checkDeriveNewFonts() {
			if (Objects.equals(lastFixedWidthFont, getFixedWidthFont())) {
				return;
			}
			lastFixedWidthFont = getFixedWidthFont();
			fixedWidthBoldFont = lastFixedWidthFont.deriveFont(Font.BOLD);
			fixedWidthItalicFont = lastFixedWidthFont.deriveFont(Font.ITALIC);
		}

		Font computeBoldFont(GTableCellRenderingData data) {
			if (data.getValue() instanceof Address) {
				checkDeriveNewFonts();
				return fixedWidthBoldFont;
			}
			return getBoldFont();
		}

		Font computeItalicFont(GTableCellRenderingData data) {
			if (data.getValue() instanceof Address) {
				checkDeriveNewFonts();
				return fixedWidthItalicFont;
			}
			return getItalicFont();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			if (!(getUnwrappedModel(data.getTable()) instanceof SnapshotTableModel model)) {
				return null;
			}
			this.model = model;
			super.getTableCellRendererComponent(data);
			SnapshotRow row = (SnapshotRow) data.getRowObject();
			DebuggerCoordinates current = model.getCurrent();
			if (row == null || current == DebuggerCoordinates.NOWHERE) {
				// When used in a dialog, only currentTrace is set
				return this;
			}
			if (current.getViewSnap() == row.getSnap()) {
				setFont(computeBoldFont(data));
			}
			else if (current.getSnap() == row.getSnap()) {
				setFont(computeItalicFont(data));
			}
			else {
				setFont(computePlainFont(data));
			}

			TraceSnapshot snapshot = row.getSnapshot();
			if (snapshot.isStale(true)) {
				setForeground(
					data.isSelected() ? COLOR_FOREGROUND_STALE_SEL : COLOR_FOREGROUND_STALE);
			}
			else {
				JTable table = data.getTable();
				setForeground(
					data.isSelected() ? table.getSelectionForeground() : table.getForeground());
			}

			return this;
		}
	}

	protected final PluginTool tool;
	protected final SnapshotTableModel snapshotTableModel;
	protected final GThreadedTablePanel<SnapshotRow> snapshotTablePanel;
	protected final GTable snapshotTable;
	protected final GhidraTableFilterPanel<SnapshotRow> snapshotFilterPanel;

	public DebuggerSnapshotTablePanel(PluginTool tool) {
		super(new BorderLayout());
		this.tool = tool;
		snapshotTableModel = new SnapshotTableModel(tool);
		snapshotTablePanel = new GThreadedTablePanel<>(snapshotTableModel);
		snapshotTable = snapshotTablePanel.getTable();

		snapshotTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(snapshotTablePanel);

		snapshotFilterPanel = new GhidraTableFilterPanel<>(snapshotTable, snapshotTableModel);
		add(snapshotFilterPanel, BorderLayout.SOUTH);
	}

	public void setTrace(Trace trace) {
		snapshotTableModel.setTrace(trace);
	}

	public Trace getTrace() {
		return snapshotTableModel.getTrace();
	}

	public void setHideScratchSnapshots(boolean hideScratch) {
		snapshotTableModel.setHideScratch(hideScratch);
	}

	public ListSelectionModel getSelectionModel() {
		return snapshotTable.getSelectionModel();
	}

	public Long getSelectedSnapshot() {
		SnapshotRow row = snapshotFilterPanel.getSelectedItem();
		return row == null ? null : row.getSnap();
	}

	public void setCurrent(DebuggerCoordinates coords) {
		boolean fire = coords.getViewSnap() != snapshotTableModel.getCurrent().getViewSnap();
		snapshotTableModel.setCurrent(coords);
		if (fire) {
			snapshotTable.repaint();
		}

		SnapshotRow row = snapshotTableModel.getRow(coords.getViewSnap());
		if (row == null) {
			return;
		}
		int viewRow = snapshotFilterPanel.getViewRow(row);
		if (viewRow == -1) {
			return;
		}
		Rectangle rect = snapshotTable.getCellRect(viewRow, 0, true);
		snapshotTable.scrollRectToVisible(rect);
	}

	public void setSelectedSnapshot(Long snap) {
		if (snap == null) {
			snapshotTable.clearSelection();
			return;
		}

		SnapshotRow sel = snapshotFilterPanel.getSelectedItem();
		Long curSnap = sel == null ? null : sel.getSnap();
		if (Objects.equals(curSnap, snap)) {
			return;
		}

		SnapshotRow row = snapshotTableModel.getRow(snap);
		if (row == null) {
			snapshotTable.clearSelection();
			return;
		}
		snapshotFilterPanel.setSelectedItem(row);
	}
}
