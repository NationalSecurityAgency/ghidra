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
import java.awt.event.KeyListener;
import java.awt.event.MouseListener;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.ListSelectionListener;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public abstract class AbstractQueryTablePanel<T> extends JPanel {

	protected final AbstractQueryTableModel<T> tableModel;
	protected final GhidraTable table;
	protected final GhidraTableFilterPanel<T> filterPanel;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	protected boolean limitToSnap = false;
	protected boolean showHidden = false;

	public AbstractQueryTablePanel(Plugin plugin) {
		super(new BorderLayout());
		tableModel = createModel(plugin);
		table = new GhidraTable(tableModel);
		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		add(new JScrollPane(table), BorderLayout.CENTER);
		add(filterPanel, BorderLayout.SOUTH);
	}

	protected abstract AbstractQueryTableModel<T> createModel(Plugin plugin);

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
			tableModel.setSpan(Range.singleton(current.getSnap()));
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
		tableModel.setSpan(limitToSnap ? Range.singleton(current.getSnap()) : Range.all());
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

	@Override
	public synchronized void addMouseListener(MouseListener l) {
		super.addMouseListener(l);
		// HACK?
		table.addMouseListener(l);
	}

	@Override
	public synchronized void removeMouseListener(MouseListener l) {
		super.removeMouseListener(l);
		// HACK?
		table.removeMouseListener(l);
	}

	@Override
	public synchronized void addKeyListener(KeyListener l) {
		super.addKeyListener(l);
		// HACK?
		table.addKeyListener(l);
	}

	@Override
	public synchronized void removeKeyListener(KeyListener l) {
		super.removeKeyListener(l);
		// HACK?
		table.removeKeyListener(l);
	}

	public void setSelectionMode(int selectionMode) {
		table.setSelectionMode(selectionMode);
	}

	public int getSelectionMode() {
		return table.getSelectionModel().getSelectionMode();
	}

	// TODO: setSelectedItems? Is a bit more work than expected:
	//  see filterPanel.getTableFilterModel();
	//  see table.getSelectionMode().addSelectionInterval()
	//  seems like setSelectedItems should be in filterPanel?

	public void setSelectedItem(T item) {
		filterPanel.setSelectedItem(item);
	}

	public boolean trySelect(TraceObject object) {
		T t = tableModel.findTraceObject(object);
		if (t == null) {
			return false;
		}
		setSelectedItem(t);
		return true;
	}

	public List<T> getSelectedItems() {
		return filterPanel.getSelectedItems();
	}

	public T getSelectedItem() {
		return filterPanel.getSelectedItem();
	}

	public void setDiffColor(Color diffColor) {
		tableModel.setDiffColor(diffColor);
	}

	public void setDiffColorSel(Color diffColorSel) {
		tableModel.setDiffColorSel(diffColorSel);
	}
}
