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
package docking.widgets.table;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JPopupMenu;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;

import docking.DockingUtils;
import docking.DockingWindowManager;
import ghidra.util.HelpLocation;

public class GTableMouseListener extends MouseAdapter {

	static {
		DockingWindowManager.getHelpService().registerHelp(GTableMouseListener.class,
			new HelpLocation("Tables", "GhidraTableHeaders"));
	}

	private GTable table;

	private boolean isDragged; // prevents popups during drag operations
	private boolean isPopup; // prevents sorting during popups
	private boolean sortingEnabled = true;

	GTableMouseListener(GTable table) {
		this.table = table;
	}

	void setSortingEnabled(boolean enabled) {
		this.sortingEnabled = enabled;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!e.isPopupTrigger()) {
			return;
		}

		processPopup(e);
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (!e.isPopupTrigger()) {
			isDragged = false; // allow popups to show since dragging is finished
			return;
		}

		processPopup(e);
	}

	private void processPopup(MouseEvent e) {
		if (!isDragged) {

			if (shouldIgnoreRightClick()) {
				return;
			}

			int columnIndex = table.columnAtPoint(e.getPoint());
			JPopupMenu menu = table.getTableColumnPopupMenu(columnIndex);
			if (menu != null) {
				isPopup = true;
				menu.show(e.getComponent(), e.getX(), e.getY());
			}
			e.consume();
		}
		else {
			isDragged = false; // allow popups to show since dragging is finished
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		boolean wasPopup = isPopup;
		isPopup = false;
		if (e.isConsumed() || wasPopup) {
			return;
		}

		// Map the mouse event x/y to the column selected on in the table.
		TableColumnModel colModel = table.getColumnModel();
		int colIndex = colModel.getColumnIndexAtX(e.getX());
		if (colIndex < 0) {
			return;
		}

		if (isHelpClick()) {
			DockingWindowManager.getHelpService().showHelp(getClass(), false, table);
			return;
		}

		if (!sortingEnabled) {
			return;
		}

		if (DockingUtils.isControlModifier(e)) {
			TableUtils.columnAlternativelySelected(table, colIndex);
		}
		else {
			TableUtils.columnSelected(table, colIndex);
		}

		if (colModel instanceof GTableColumnModel) {
			// save the sort state
			((GTableColumnModel) colModel).saveState();
		}
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		isDragged = true;
	}

	private boolean isHelpClick() {
		JTableHeader tableHeader = table.getTableHeader();
		if (!(tableHeader instanceof GTableHeader)) {
			return false;
		}

		GTableHeader tooltipTableHeader = (GTableHeader) tableHeader;
		return tooltipTableHeader.isMouseOverHelpIcon();
	}

	private boolean shouldIgnoreRightClick() {
		return isHelpClick();
	}
}
