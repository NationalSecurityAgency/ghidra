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

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ChangeListener;

import docking.actions.KeyBindingUtils;
import generic.theme.GIcon;

/**
 * Class for displaying a view into a {@link CoordinatedStructureModel}, showing either the
 * left structure, the right structure, or the merged structure. It consists of a JList in
 * a JScrollpane where the list model is extracted from the {@link CoordinatedStructureModel} for
 * either the left,right, or merged view. These views track together for both view scrolling and
 * list selection. They all share a {@link DisplayCoordinator} that assists with coordinating the
 * views.
 */
public class CoordinatedStructureDisplay extends JPanel {
	public static final int MARGIN = 10;

	static Icon APPLY_ICON = new GIcon("icon.base.merge.struct.apply");

	private JList<ComparisonItem> jList;
	private JScrollPane scroll;
	private JScrollBar horizontalScrollbar;
	private JScrollBar verticalScrollbar;

	private String title;
	private StructDisplayModel listModel;
	private int rowHeight;

	private ComparisonItemRenderer renderer;

	private DisplayCoordinator coordinator;

	public CoordinatedStructureDisplay(String title, StructDisplayModel listModel,
			DisplayCoordinator coordinator) {
		super(new BorderLayout());
		this.title = title;
		this.listModel = listModel;
		this.coordinator = coordinator;
		Border emptyBorder = BorderFactory.createEmptyBorder(10, 0, 0, 0);
		setBorder(BorderFactory.createTitledBorder(emptyBorder, title));
		renderer = new ComparisonItemRenderer(listModel);
		jList = new JList<ComparisonItem>(listModel);
		rowHeight = Math.max(renderer.getPreferredHeight(), APPLY_ICON.getIconHeight() + 6);
		jList.setFixedCellHeight(rowHeight);
		jList.setCellRenderer(renderer);
		jList.setBorder(
			BorderFactory.createEmptyBorder(MARGIN, MARGIN, MARGIN, MARGIN));
		jList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		// remove key bindings so we can assign them to our actions
		clearBinding("SPACE");
		clearBinding("LEFT");
		clearBinding("RIGHT");

		scroll = new JScrollPane(jList);
		horizontalScrollbar = scroll.getHorizontalScrollBar();
		verticalScrollbar = scroll.getVerticalScrollBar();
		add(scroll);
		jList.addListSelectionListener(e -> notifyCoordiatorSelectionChanged());
		horizontalScrollbar
				.addAdjustmentListener(e -> coordinator.notifyHorizontalScrollChanged(this, e));
		verticalScrollbar
				.addAdjustmentListener(e -> coordinator.notifyVerticalScrollChanged(this, e));
		coordinator.registerDisplay(this);
	}

	@Override
	public String toString() {
		return title;
	}

	/**
	 * Sets the list item to be selected based on the the selection change of the given display.
	 * @param changedDisplay the display that was changed by the user and is being used to update
	 * the other displays.
	 * @param index the list index that was selected in the given display.
	 * @param item the comparison item that was selected the the given display.
	 */
	void setSelectedItem(CoordinatedStructureDisplay changedDisplay, int index,
			ComparisonItem item) {
		if (changedDisplay == this) {
			return;
		}

		// If the models have different sizes, find the index of the corresponding item using
		// the line number from the item. Otherwise, the list index can be used directly.
		if (changedDisplay.getItemCount() != getItemCount()) {
			index = listModel.getIndex(item);
		}

		if (index < 0) {
			jList.clearSelection();
		}
		else {
			jList.setSelectedIndex(index);
		}
	}

	/**
	 * Sets the horizontal scroll position based on the view change in one of the other displays.
	 * @param changedDisplay the display that was changed by the user.
	 * @param value the horizontal scroll position of the given display.
	 */
	void setHorizontalScroll(CoordinatedStructureDisplay changedDisplay, int value) {
		if (changedDisplay == this) {
			return;
		}
		horizontalScrollbar.setValue(value);
	}

	/**
	 * Sets the vertical scroll position based on the view change in one of the other displays.
	 * @param changedDisplay the display that was changed by the user. Coordinating the vertical
	 * position can be tricky because the merged display has had its blank lines removed. If the
	 * model sizes are different, it uses the line number information in the displayed items to
	 * compute the corresponding position.
	 * @param value the vertical scroll position of the given display.
	 */
	void setVerticalScroll(CoordinatedStructureDisplay changedDisplay, int value) {
		if (this == changedDisplay) {
			return;
		}
		if (getItemCount() == changedDisplay.getItemCount()) {
			// If the models are the same size, we can use the vertical scroll position directly
			verticalScrollbar.setValue(value);
		}
		else {
			// Otherwise, we have to find the corresponding first object in the other display.
			int idx = changedDisplay.getFirstVisibleIndex();
			if (idx < 0) {
				return;
			}
			Rectangle r = changedDisplay.jList.getCellBounds(idx, idx);
			ComparisonItem first = changedDisplay.getFirstVisibleItem();

			// We also compute a vertical line offset so that if the first item has a match and
			// is partially scrolled off the screen, we can partially scroll this display to match.
			int offset = r.y - value;

			int index = listModel.getIndex(first);
			if (index < 0) {
				offset = 0; 	// don't partial scroll for inexact match
				index = -index - 1;
			}
			Rectangle cellBounds = jList.getCellBounds(index, index);
			verticalScrollbar.setValue(cellBounds.y - offset);
		}

	}

	ComparisonItem getItem(int index) {
		return listModel.getElementAt(index);
	}

	int getRowHeight() {
		return rowHeight;
	}

	void setRowHeight(int rowHeight) {
		this.rowHeight = rowHeight;
		jList.setFixedCellHeight(rowHeight);
	}

	int getFirstVisibleIndex() {
		return jList.getFirstVisibleIndex();
	}

	int getLastVisibleIndex() {
		return jList.getLastVisibleIndex();
	}

	ComparisonItem getSelectedItem() {
		return jList.getSelectedValue();
	}

	Component getList() {
		return jList;
	}

	void addViewportListener(ChangeListener l) {
		scroll.getViewport().addChangeListener(l);
	}

	private int getItemCount() {
		return listModel.getSize();
	}

	private void clearBinding(String keyName) {
		KeyBindingUtils.clearKeyBinding(jList, KeyBindingUtils.parseKeyStroke(keyName));
		KeyBindingUtils.clearKeyBinding(jList, KeyBindingUtils.parseKeyStroke("ctrl " + keyName));
		KeyBindingUtils.clearKeyBinding(jList, KeyBindingUtils.parseKeyStroke("shift " + keyName));
		KeyBindingUtils.clearKeyBinding(jList,
			KeyBindingUtils.parseKeyStroke("ctrl shift " + keyName));
	}

	private void notifyCoordiatorSelectionChanged() {
		int selectedIndex = jList.getSelectedIndex();
		ComparisonItem item = jList.getSelectedValue();
		coordinator.notifySelectionChanged(this, selectedIndex, item);

	}

	private ComparisonItem getFirstVisibleItem() {
		int index = jList.getFirstVisibleIndex();
		if (index >= 0) {
			return listModel.getElementAt(index);
		}
		return null;
	}

}
