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
package docking.widgets.searchlist;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.function.*;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.*;

import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.list.GListCellRenderer;
import utility.function.Dummy;

/**
 * Component for displaying and selecting from a filterable list of items that are grouped into
 * categories. Similar to a JList, but with filtering and grouping.
 *
 * @param <T> the type of items in the list
 */
public class SearchList<T> extends JPanel {
	private SearchListModel<T> model;
	private JList<SearchListEntry<T>> jList;
	private int categoryWidth;
	private JTextField textField;
	private BiConsumer<T, String> chosenItemCallback;
	private Consumer<T> selectedConsumer = Dummy.consumer();
	private ListCellRenderer<SearchListEntry<T>> itemRenderer = new DefaultItemRenderer();
	private String currentFilterText;
	private boolean showCategories = true;
	private boolean singleClickMode = false;
	private BiFunction<T, String, String> displayNameFunction = (t, c) -> t.toString();

	/**
	 * Construct a new SearchList given a model and an chosen item callback.
	 * @param model the model containing the group list items
	 * @param chosenItemCallback the callback to be notified when an item is chosen (enter key 
	 * pressed)
	 */
	public SearchList(SearchListModel<T> model, BiConsumer<T, String> chosenItemCallback) {
		super(new BorderLayout());
		this.model = model;
		this.chosenItemCallback = Dummy.ifNull(chosenItemCallback);

		add(buildList(), BorderLayout.CENTER);
		add(buildFilterField(), BorderLayout.NORTH);
		model.addListDataListener(new SearchListDataListener());
		modelChanged();
	}

	/**
	 * Returns the current filter text
	 * @return the current filter text
	 */
	public String getFilterText() {
		return textField.getText();
	}

	/**
	 * Returns the search list model.
	 * @return the model
	 */
	public SearchListModel<T> getModel() {
		return model;
	}

	/**
	 * Sets the current filter text
	 * @param text the text to set as the current filter
	 */
	public void setFilterText(String text) {
		textField.setText(text);
	}

	/**
	 * Gets the currently selected item.
	 * @return the currently selected item.
	 */
	public T getSelectedItem() {
		SearchListEntry<T> entry = jList.getSelectedValue();
		if (entry != null) {
			return entry.value();
		}
		return null;
	}

	public void setSelectedItem(T t) {
		ListModel<SearchListEntry<T>> listModel = jList.getModel();
		for (int i = 0; i < listModel.getSize(); i++) {
			SearchListEntry<T> entry = listModel.getElementAt(i);
			if (entry.value().equals(t)) {
				jList.setSelectedIndex(i);
				return;
			}
		}
	}

	/**
	 * Sets a consumer to be notified whenever the selected item changes.
	 * @param consumer the consumer to be notified whenever the selected item changes.
	 */
	public void setSelectionCallback(Consumer<T> consumer) {
		this.selectedConsumer = Dummy.ifNull(consumer);
	}

	/**
	 * Sets a custom sub-renderer for displaying list items. Note: this renderer is only used to
	 * render the item, not the category. 
	 * @param itemRenderer the sub_renderer for rendering the list items, but not the entire line
	 * which includes the category.
	 */
	public void setItemRenderer(ListCellRenderer<SearchListEntry<T>> itemRenderer) {
		this.itemRenderer = itemRenderer;
	}

	/**
	 * Resets the selection to the first element
	 */
	public void setInitialSelection() {
		jList.clearSelection();
	}

	/**
	 * Sets an option to display categories in the list or not.
	 * @param b true to show categories, false to not shoe them
	 */
	public void setShowCategories(boolean b) {
		showCategories = b;
	}

	/**
	 * Sets an option for the list to respond to either double or single mouse clicks. By default,
	 * it responds to a double click.
	 * @param b true for single click mode, false for double click mode
	 */
	public void setSingleClickMode(boolean b) {
		singleClickMode = b;
	}

	public void setDisplayNameFunction(BiFunction<T, String, String> nameFunction) {
		this.displayNameFunction = nameFunction;
	}

	public void setMouseHoverSelection() {
		jList.addMouseMotionListener(new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				int index = jList.locationToIndex(e.getPoint());
				if (index >= 0) {
					jList.setSelectedIndex(index);
				}
			}
		});
	}

	/**
	 * Disposes the component and clears all the model data
	 */
	public void dispose() {
		model.dispose();
	}

	private String getDisplayName(T value, String category) {
		return displayNameFunction.apply(value, category);
	}

	private Component buildList() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
		jList = new JList<SearchListEntry<T>>(model);
		JScrollPane jScrollPane = new JScrollPane(jList);
		jScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jList.setCellRenderer(new SearchListRenderer());
		jList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		jList.addKeyListener(new ListKeyListener());
		jList.setVisibleRowCount(Math.min(model.getSize(), 20));
		jList.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			T selectedItem = getSelectedItem();
			selectedConsumer.accept(selectedItem);
		});
		jList.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (singleClickMode && e.getButton() == MouseEvent.BUTTON1) {
					chooseItem();
					return;
				}
				super.mouseClicked(e);
			}

			@Override
			public void doubleClickTriggered(MouseEvent e) {
				chooseItem();
			}
		});
		panel.add(jScrollPane, BorderLayout.CENTER);
		return panel;
	}

	private Component buildFilterField() {
		JPanel panel = new JPanel(new BorderLayout());
		textField = new JTextField();
		panel.add(textField, BorderLayout.CENTER);
		textField.addKeyListener(new TextFieldKeyListener());
		textField.getDocument().addDocumentListener(new SearchListDocumentListener());
		return panel;
	}

	protected void moveListUpDown(boolean isUp) {
		int index = jList.getSelectedIndex();
		if (isUp) {
			if (index > 0) {
				jList.setSelectedIndex(index - 1);
			}
		}
		else if (index < model.getSize() - 1) {
			jList.setSelectedIndex(index + 1);
		}
	}

	private void modelChanged() {
		categoryWidth = computeCategoryWidth();
		setInitialSelection();
	}

	private int computeCategoryWidth() {
		int width = 0;
		List<String> categories = model.getCategories();
		Font font = jList.getFont();
		FontMetrics metrics = jList.getFontMetrics(font);
		for (String category : categories) {
			width = Math.max(width, metrics.stringWidth(category));
		}
		return width + 10;
	}

	public void chooseItem() {
		SearchListEntry<T> selectedValue = jList.getSelectedValue();
		if (selectedValue != null) {
			chosenItemCallback.accept(selectedValue.value(), selectedValue.category());
		}
	}

	private void filterTextChanged() {
		String newFilterText = textField.getText().trim();
		if (!newFilterText.equals(currentFilterText)) {
			currentFilterText = newFilterText;
			model.setFilter(createFilter(currentFilterText));
		}
	}

	protected BiPredicate<T, String> createFilter(String text) {
		return new DefaultFilter(text);
	}

	JTextField getTextField() {
		return textField;
	}

	private class SearchListRenderer implements ListCellRenderer<SearchListEntry<T>> {
		private JPanel panel;
		private JLabel categoryLabel;
		private Border normalBorder;
		private Border lastEntryBorder;
		private JSeparator jSeparator;

		SearchListRenderer() {
			categoryLabel = new JLabel();
			panel = new JPanel(new BorderLayout());
			jSeparator = new JSeparator();
			int separatorHeight = jSeparator.getPreferredSize().height;
			normalBorder = BorderFactory.createEmptyBorder(1, 5, separatorHeight, 5);
			lastEntryBorder = BorderFactory.createEmptyBorder(1, 5, 0, 5);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends SearchListEntry<T>> list,
				SearchListEntry<T> value, int index, boolean isSelected, boolean cellHasFocus) {
			panel.removeAll();
			categoryLabel.setText("");
			panel.setBorder(normalBorder);

			// only display the category for the first entry in that category
			if (value.showCategory()) {
				categoryLabel.setText(value.category());
			}

			// Display a separator at the bottom of the last entry in the category to make
			// category boundaries
			if (value.drawSeparator()) {
				panel.setBorder(lastEntryBorder);
				panel.add(jSeparator, BorderLayout.SOUTH);
			}
			Dimension size = categoryLabel.getPreferredSize();
			categoryLabel.setPreferredSize(new Dimension(categoryWidth, size.height));
			Component itemRendererComp =
				itemRenderer.getListCellRendererComponent(list, value, index, isSelected, false);

			Color background = itemRendererComp.getBackground();
			if (showCategories) {
				panel.add(categoryLabel, BorderLayout.WEST);
			}
			panel.add(itemRendererComp, BorderLayout.CENTER);
			panel.setBackground(background);
			categoryLabel.setOpaque(true);
			categoryLabel.setBackground(background);
			categoryLabel.setForeground(itemRendererComp.getForeground());
			panel.getAccessibleContext()
					.setAccessibleName(getDisplayName(value.value(), value.category()));
			return panel;
		}
	}

	private class DefaultItemRenderer extends GListCellRenderer<SearchListEntry<T>> {

		@Override
		public Component getListCellRendererComponent(JList<? extends SearchListEntry<T>> list,
				SearchListEntry<T> value, int index, boolean isSelected, boolean hasFocus) {

			JLabel label =
				(JLabel) super.getListCellRendererComponent(list, value, index, isSelected, false);
			SearchListEntry<T> entry = value;
			T t = entry.value();
			label.setText(t.toString());

			return label;
		}
	}

	private class SearchListDataListener implements ListDataListener {

		@Override
		public void intervalAdded(ListDataEvent e) {
			modelChanged();
		}

		@Override
		public void intervalRemoved(ListDataEvent e) {
			modelChanged();
		}

		@Override
		public void contentsChanged(ListDataEvent e) {
			modelChanged();
		}
	}

	private class TextFieldKeyListener extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent e) {
			int keyCode = e.getKeyCode();
			if (keyCode == KeyEvent.VK_ENTER) {
				chooseItem();
			}
			else if (keyCode == KeyEvent.VK_UP || keyCode == KeyEvent.VK_DOWN) {
				KeyboardFocusManager.getCurrentKeyboardFocusManager().redispatchEvent(jList, e);
				jList.requestFocus();
			}
		}
	}

	private class ListKeyListener extends KeyAdapter {
		@Override
		public void keyTyped(KeyEvent e) {
			if (e.getKeyChar() == '\n') {
				chooseItem();

			}
			int keyCode = e.getKeyChar();
			if (keyCode == KeyEvent.VK_ENTER) {
				chooseItem();
			}

			KeyboardFocusManager.getCurrentKeyboardFocusManager().redispatchEvent(textField, e);
			textField.requestFocus();
		}
	}

	private class SearchListDocumentListener implements DocumentListener {

		@Override
		public void insertUpdate(DocumentEvent e) {
			filterTextChanged();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			filterTextChanged();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			filterTextChanged();
		}

	}

	private class DefaultFilter implements BiPredicate<T, String> {
		private String filterText;

		DefaultFilter(String filterText) {
			this.filterText = filterText.toLowerCase();
		}

		@Override
		public boolean test(T t, String category) {
			return getDisplayName(t, category).toLowerCase().contains(filterText);
		}
	}

	public JTextField getFilterField() {
		return textField;
	}

}
