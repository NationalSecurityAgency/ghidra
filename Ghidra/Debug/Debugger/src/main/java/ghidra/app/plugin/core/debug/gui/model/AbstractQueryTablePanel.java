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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.*;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public abstract class AbstractQueryTablePanel<T, M extends AbstractQueryTableModel<T>>
		extends JPanel {

	public interface CellActivationListener {
		void cellActivated(JTable table);
	}

	protected final M tableModel;
	protected final GhidraTable table;
	protected final GhidraTableFilterPanel<T> filterPanel;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected boolean limitToSnap = false;
	protected boolean showHidden = false;

	private final ListenerSet<CellActivationListener> cellActivationListeners =
		new ListenerSet<>(CellActivationListener.class);

	public AbstractQueryTablePanel(Plugin plugin) {
		super(new BorderLayout());
		tableModel = createModel(plugin);
		table = new GhidraTable(tableModel);
		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		add(new JScrollPane(table), BorderLayout.CENTER);
		add(filterPanel, BorderLayout.SOUTH);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					fireCellActivated();
				}
			}
		});
		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					fireCellActivated();
					e.consume();
				}
			}
		});
	}

	protected abstract M createModel(Plugin plugin);

	public void goToCoordinates(DebuggerCoordinates coords) {
		if (DebuggerCoordinates.equalsIgnoreRecorderAndView(current, coords)) {
			return;
		}
		DebuggerCoordinates previous = current;
		this.current = coords;
		if (previous.getSnap() == current.getSnap() &&
			previous.getTrace() == current.getTrace()) {
			return;
		}
		tableModel.setDiffTrace(previous.getTrace());
		tableModel.setTrace(current.getTrace());
		tableModel.setDiffSnap(previous.getSnap());
		tableModel.setSnap(current.getSnap());
		if (limitToSnap) {
			tableModel.setSpan(Lifespan.at(current.getSnap()));
		}
	}

	public void reload() {
		tableModel.reload();
	}

	public void setQuery(ModelQuery query) {
		tableModel.setQuery(query);
	}

	public ModelQuery getQuery() {
		return tableModel.getQuery();
	}

	public void setLimitToSnap(boolean limitToSnap) {
		if (this.limitToSnap == limitToSnap) {
			return;
		}
		this.limitToSnap = limitToSnap;
		tableModel.setSpan(limitToSnap ? Lifespan.at(current.getSnap()) : Lifespan.ALL);
	}

	public boolean isLimitToSnap() {
		return limitToSnap;
	}

	public void setShowHidden(boolean showHidden) {
		if (this.showHidden == showHidden) {
			return;
		}
		this.showHidden = showHidden;
		tableModel.setShowHidden(showHidden);
	}

	public boolean isShowHidden() {
		return showHidden;
	}

	public void addSelectionListener(ListSelectionListener listener) {
		table.getSelectionModel().addListSelectionListener(listener);
	}

	public void removeSelectionListener(ListSelectionListener listener) {
		table.getSelectionModel().removeListSelectionListener(listener);
	}

	public void addCellActivationListener(CellActivationListener listener) {
		cellActivationListeners.add(listener);
	}

	public void removeCellActivationListener(CellActivationListener listener) {
		cellActivationListeners.remove(listener);
	}

	public void addSeekListener(SeekListener listener) {
		tableModel.addSeekListener(listener);
	}

	public void setSelectionMode(int selectionMode) {
		table.setSelectionMode(selectionMode);
	}

	public int getSelectionMode() {
		return table.getSelectionModel().getSelectionMode();
	}

	public void setSelectedItem(T item) {
		filterPanel.setSelectedItem(item);
	}

	public void setSelectedItems(Collection<T> items) {
		table.clearSelection();
		for (T t : items) {
			int modelRow = tableModel.getRowIndex(t);
			int viewRow = filterPanel.getViewRow(modelRow);
			table.getSelectionModel().addSelectionInterval(viewRow, viewRow);
		}
		table.scrollToSelectedRow();
	}

	public boolean trySelect(TraceObject object) {
		T t = tableModel.findTraceObject(object);
		if (t == null) {
			return false;
		}
		setSelectedItem(t);
		return true;
	}

	public void trySelect(Collection<TraceObject> objects) {
		List<T> ts = objects.stream().map(tableModel::findTraceObject).collect(Collectors.toList());
		setSelectedItems(ts);
	}

	public List<T> getSelectedItems() {
		return filterPanel.getSelectedItems();
	}

	public T getSelectedItem() {
		return filterPanel.getSelectedItem();
	}

	public List<T> getAllItems() {
		return List.copyOf(tableModel.getModelData());
	}

	@SuppressWarnings("unchecked")
	public <V> Map.Entry<Integer, DynamicTableColumn<T, V, Trace>> getColumnByNameAndType(
			String name, Class<V> type) {
		int count = tableModel.getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<T, ?, ?> column = tableModel.getColumn(i);
			if (!name.equals(column.getColumnName())) {
				continue;
			}
			if (column.getColumnClass() != type) {
				continue;
			}
			return Map.entry(table.convertColumnIndexToView(i),
				(DynamicTableColumn<T, V, Trace>) column);
		}
		return null;
	}

	public void setDiffColor(Color diffColor) {
		tableModel.setDiffColor(diffColor);
	}

	public void setDiffColorSel(Color diffColorSel) {
		tableModel.setDiffColorSel(diffColorSel);
	}

	protected void fireCellActivated() {
		cellActivationListeners.fire.cellActivated(table);
	}
}
