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

import java.awt.event.*;

import docking.widgets.table.GTable;

/**
 * A listener for tables that support drag and drop operations.  This listener allows the user to
 * make a multi-selection in the table and drag that selection.
 */
public class DragDropTableSelectionMouseListener extends MouseAdapter {

	private boolean consuming = false;
	private boolean didDrag = false;
	private GTable table;

	public DragDropTableSelectionMouseListener(GTable table) {
		this.table = table;
		install();
	}

	private void install() {

		//
		// Insert our listener into the front of the listeners so that we get a chance to
		// handle events first.
		//
		MouseListener[] oldMouseListeners = table.getMouseListeners();
		MouseMotionListener[] oldMouseMotionListeners = table.getMouseMotionListeners();
		for (MouseListener l : oldMouseListeners) {
			table.removeMouseListener(l);
		}
		for (MouseMotionListener l : oldMouseMotionListeners) {
			table.removeMouseMotionListener(l);
		}

		table.addMouseListener(this);
		table.addMouseMotionListener(this);

		for (MouseListener l : oldMouseListeners) {
			table.addMouseListener(l);
		}
		for (MouseMotionListener l : oldMouseMotionListeners) {
			table.addMouseMotionListener(l);
		}
	}

	@Override
	public void mousePressed(MouseEvent e) {
		consuming = maybeConsumeEvent(e);
		didDrag = false;
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (!consuming) {
			return;
		}

		// continue to consume the event that was started during the pressed event, for symmetry
		maybeConsumeEvent(e);
		consuming = false;

		if (!didDrag) {
			//
			// If we dragged, leave the initial selection, which does not disrupt the user's
			// workflow; otherwise, select the clicked row.   This allows users to change the
			// selection by clicking in the table, which is the default table behavior.
			//
			table.clearSelection();
			int row = table.rowAtPoint(e.getPoint());
			table.selectRow(row);
		}
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		if (!consuming) {
			// This can happen when the initial left mouse click was not on a selected row.  In that
			// case we want to the drag to make a table selection.
			return;
		}

		// always consume the drag so that Java does not change the selection
		e.consume();
		didDrag = true;
	}

	private boolean maybeConsumeEvent(MouseEvent e) {

		if (!isBasicLeftClick(e)) {
			return false;
		}

		// don't let other listeners process the event if we are 'pressing' the mouse
		// button on an already selected row (to prevent de-selecting a multi-selection for
		// a drag operation)
		int row = table.rowAtPoint(e.getPoint());
		if (table.isRowSelected(row)) {
			e.consume();
			return true;
		}

		return false;
	}

	private boolean isBasicLeftClick(MouseEvent e) {

		if (e.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		if (e.getClickCount() > 1) {
			return false;
		}

		if (e.isControlDown() || e.isAltDown() || e.isShiftDown() || e.isMetaDown()) {
			return false;
		}

		return true;
	}

}
