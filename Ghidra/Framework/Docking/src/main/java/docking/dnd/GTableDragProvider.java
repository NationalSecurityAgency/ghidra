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
package docking.dnd;

import java.awt.Cursor;
import java.awt.Point;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.InputEvent;
import java.util.*;

import javax.swing.ListSelectionModel;

import docking.widgets.table.GTable;
import docking.widgets.table.RowObjectTableModel;

/**
 * A class to allow GTables to support drag operations.
 *
 * @param <ROW_OBJECT> the row object type
 */
public abstract class GTableDragProvider<ROW_OBJECT>
		implements DragSourceListener, DragGestureListener {

	protected GTable table;
	protected RowObjectTableModel<ROW_OBJECT> rowObjectModel;

	public GTableDragProvider(GTable table, RowObjectTableModel<ROW_OBJECT> model) {
		this.table = table;
		this.rowObjectModel = model;

		// install table mouse selection fixing listener
		new DragDropTableSelectionMouseListener(table);

		int actions = DnDConstants.ACTION_COPY;
		DragSource dragSource = DragSource.getDefaultDragSource();
		dragSource.createDefaultDragGestureRecognizer(table, actions, this);
	}

	/**
	 * Creates a transferable for dragging using the given selected row objects.
	 * @param items the selected row objects
	 * @return the transferable
	 */
	protected abstract Transferable createDragTransferable(List<ROW_OBJECT> items);

//=================================================================================================
// DragSourceListener methods
//=================================================================================================

	@Override
	public void dragDropEnd(DragSourceDropEvent dsde) {
		// don't care
	}

	@Override
	public void dragEnter(DragSourceDragEvent dsde) {
		// don't care
	}

	@Override
	public void dragExit(DragSourceEvent dse) {
		setCursor(DnDConstants.ACTION_NONE, dse.getDragSourceContext());
	}

	private void setCursor(int action, DragSourceContext dragSourceContext) {
		Cursor cursor = DragSource.DefaultCopyNoDrop;
		switch (action) {
			case DnDConstants.ACTION_COPY:
				cursor = DragSource.DefaultCopyDrop;
				break;
			case DnDConstants.ACTION_MOVE:
				cursor = DragSource.DefaultMoveDrop;
				break;
			case DnDConstants.ACTION_LINK:
				cursor = DragSource.DefaultLinkDrop;
		}
		dragSourceContext.setCursor(cursor);
	}

	@Override
	public void dragOver(DragSourceDragEvent dsde) {
		setCursor(dsde.getDropAction(), dsde.getDragSourceContext());
	}

	@Override
	public void dropActionChanged(DragSourceDragEvent dsde) {
		// don't care
	}

//=================================================================================================
// DragGestureListener methods
//=================================================================================================	

	@Override
	public void dragGestureRecognized(DragGestureEvent dragEvent) {

		// check input event: if any button other than MB1 is pressed,
		// don't attempt to process the drag and drop event.
		InputEvent ie = dragEvent.getTriggerEvent();
		int modifiers = ie.getModifiersEx();
		if ((modifiers & InputEvent.BUTTON2_DOWN_MASK) != 0 ||
			(modifiers & InputEvent.BUTTON3_DOWN_MASK) != 0) {
			return;
		}

		List<ROW_OBJECT> items = getSelectedItems();
		if (items.isEmpty()) {
			return;
		}
		Transferable transferable = createDragTransferable(items);
		if (transferable == null) {
			return;
		}

		try {
			dragEvent.startDrag(DragSource.DefaultMoveDrop, null, new Point(0, 0), transferable,
				this);
		}
		catch (InvalidDnDOperationException exc) {
			// not sure why, but apparently we don't care
		}
	}

	protected List<ROW_OBJECT> getSelectedItems() {

		ListSelectionModel lsm = table.getSelectionModel();
		if (lsm.getValueIsAdjusting()) {
			// don't allow dragging while a selection is being made
			return Collections.emptyList();
		}

		int[] rows = table.getSelectedRows();
		List<ROW_OBJECT> objects = new ArrayList<>();
		for (int row : rows) {
			ROW_OBJECT ro = rowObjectModel.getRowObject(row);
			objects.add(ro);
		}
		return objects;
	}
}
