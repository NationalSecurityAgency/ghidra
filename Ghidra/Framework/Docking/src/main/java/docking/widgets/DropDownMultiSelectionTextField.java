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
package docking.widgets;

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Extension of the {@link DropDownSelectionTextField} that allows multiple items to
 * be selected. 
 * <p>
 * Note that multiple selection introduces some display complications that are not an 
 * issue with single selection. Namely:
 * <ul>
 * <li>how do you display multiple selected items in the preview pane</li>
 * <li>how do you display those same items in the drop down text field</li>
 * </ul>
 * The solution here is to:
 * <ul>
 * <li>let the preview panel operate normally; it will simply display the preview text for whatever was last selected</li>
 * <li>display all selected items in the drop down text field as a comma-delimited list</li>
 * </ul>
 *
 * @param <T> the type of data stored in the drop down
 */
public class DropDownMultiSelectionTextField<T> extends DropDownSelectionTextField<T> {

	private JList<String> previewList;
	private List<T> selectedValues = new ArrayList<>();
	private WeakSet<DropDownMultiSelectionChoiceListener<T>> choiceListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	/**
	 * Constructor.
	 * 
	 * @param dataModel the model for the drop down widget
	 */
	public DropDownMultiSelectionTextField(DropDownTextFieldDataModel<T> dataModel) {
		super(dataModel);
	}

	/**
	 * Adds the caller to a list of subscribers who will be notified when selection changes.
	 * 
	 * @param listener the subscriber to be added
	 */
	public void addDropDownSelectionChoiceListener(
			DropDownMultiSelectionChoiceListener<T> listener) {
		choiceListeners.add(listener);
	}

	@Override
	public void addDropDownSelectionChoiceListener(DropDownSelectionChoiceListener<T> listener) {
		throw new UnsupportedOperationException(
			"Please use the flavor of this method that takes a DropDownMultiSelectionChoiceListener instance.");
	}

	/**
	 * Returns a list of all selected items in the list.
	 * 
	 * @return the selected items
	 */
	public List<T> getSelectedValues() {
		return selectedValues;
	}

	@Override
	protected ListSelectionModel createListSelectionModel() {
		DefaultListSelectionModel model = new DefaultListSelectionModel();
		model.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		return model;
	}

	@Override
	protected void setPreviewPaneAttributes() {
		if (previewList == null) {
			previewList = new JList<>();
		}
		previewList.setOpaque(true);
		previewList.setBackground(TOOLTIP_WINDOW_BGCOLOR);
		previewList.setFocusable(false);
		previewList.setModel(new DefaultListModel<String>());
	}

	@Override
	protected boolean hasPreview() {
		return previewList.getModel().getSize() > 0;
	}

	@Override
	protected ListSelectionListener getPreviewListener() {
		return new PreviewListener();
	}

	@Override
	protected JComponent getPreviewPaneComponent() {
		return previewList;
	}

	@Override
	protected void setTextFromList() {
		List<T> selectedItems = list.getSelectedValuesList();
		if (selectedItems != null && !selectedItems.isEmpty()) {
			storeSelectedValues(selectedItems);
			String allValues = getSelectionText();
			setText(allValues);
			hideMatchingWindow();
			fireUserChoiceMade(selectedItems);
		}
	}

	@Override
	public void setSelectedValue(T value) {
		ArrayList<T> values = new ArrayList<>();
		values.add(value);
		storeSelectedValues(values);

		if (value != null) {
			setText(dataModel.getDisplayText(value));
			setToolTipText(dataModel.getDescription(value));
		}
		else {
			setText("");
			setToolTipText("");
		}
	}

	@Override
	protected void setTextFromSelectedListItemAndKeepMatchingWindowOpen() {
		List<T> selectedItems = list.getSelectedValuesList();
		if (selectedItems != null && !selectedItems.isEmpty()) {
			internallyDrivenUpdate = true;
			storeSelectedValues(selectedItems);
			String allValues = getSelectedText();
			setTextWithoutClosingCompletionWindow(allValues);
			fireUserChoiceMade(selectedItems);
		}
	}

	/**
	 * Returns a string representing all items selected in the pulldown. If multiple
	 * items are selected, they will be comma-delimited.
	 * 
	 * @return the comma-delimited selection
	 */
	private String getSelectionText() {

		List<String> values = new ArrayList<>();
		for (T t : selectedValues) {
			values.add(dataModel.getDisplayText(t));
		}

		return StringUtils.join(values.iterator(), ",");
	}

	/**
	 * Notifies subscribers when the list selection has changed.
	 * 
	 * @param selectedItems the list of selected items
	 */
	private void fireUserChoiceMade(List<T> selectedItems) {
		for (DropDownMultiSelectionChoiceListener<T> listener : choiceListeners) {
			listener.selectionChanged(selectedItems);
		}
	}

	/**
	 * Saves the selected list items.
	 * 
	 * @param newValues the new selected items
	 */
	private void storeSelectedValues(List<T> newValues) {
		selectedValues.clear();
		selectedValues.addAll(newValues);
	}

	/**
	 * Listener for the preview panel which is kicked whenever a selection has been
	 * made in the drop down. This will prompt the preview panel to change what it
	 * displays.
	 */
	private class PreviewListener implements ListSelectionListener {

		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (!e.getValueIsAdjusting()) {
				DefaultListModel<String> model = (DefaultListModel<String>) previewList.getModel();
				model.clear();

				List<T> values = list.getSelectedValuesList();
				for (T value : values) {
					model.addElement(dataModel.getDescription(value));
				}
			}
		}
	}
}
