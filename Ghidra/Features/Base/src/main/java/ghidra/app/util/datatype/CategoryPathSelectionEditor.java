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
package ghidra.app.util.datatype;

import java.awt.Component;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.TreePath;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.button.BrowseButton;
import docking.widgets.list.GListCellRenderer;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.CategoryPath;
import ghidra.util.exception.AssertException;

/**
 * An editor that is used to show the {@link DropDownSelectionTextField} for the entering of
 * category paths by name and offers the user of a completion window.  This editor also provides a
 * browse button that when pressed will show a data type tree so that the user may browse a tree
 * of known category paths.
 * <p>
 * <u>Stand Alone Usage</u><br>
 * In order to use this component directly you need to call {@link #getEditorComponent()}.  This
 * will give you a Component for editing.
 * <p>
 * In order to know when changes are made to the component you need to add a DocumentListener
 * via the {@link #addDocumentListener(DocumentListener)} method.  The added listener will be
 * notified as the user enters text into the editor's text field.
 */
public class CategoryPathSelectionEditor extends AbstractCellEditor {

	private JPanel editorPanel;
	private DropDownSelectionTextField<CategoryPath> selectionField;
	private JButton browseButton;
	private DataTypeManagerService dataTypeManagerService;

	private KeyAdapter keyListener;
	private NavigationDirection navigationDirection;

	// optional path to initially select in the data type chooser tree
	private TreePath initiallySelectedTreePath;

	/**
	 * Creates a new instance.
	 * 
	 * @param serviceProvider {@link ServiceProvider} 
	 */
	public CategoryPathSelectionEditor(ServiceProvider serviceProvider) {

		this.dataTypeManagerService = serviceProvider.getService(DataTypeManagerService.class);

		if (this.dataTypeManagerService == null) {
			throw new NullPointerException("DataTypeManagerService cannot be null");
		}
		init();
	}

	/**
	 * Sets whether this editor should consumer Enter key presses
	 * @see DropDownSelectionTextField#setConsumeEnterKeyPress(boolean)
	 *
	 * @param consume true to consume
	 */
	public void setConsumeEnterKeyPress(boolean consume) {
		selectionField.setConsumeEnterKeyPress(consume);
	}

	protected DropDownSelectionTextField<CategoryPath> createDropDownSelectionTextField(
			CategoryPathDropDownSelectionDataModel model) {
		return new DropDownSelectionTextField<>(model);
	}

	private void init() {
		selectionField = createDropDownSelectionTextField(
			new CategoryPathDropDownSelectionDataModel(dataTypeManagerService));
		selectionField.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				fireEditingCanceled();
				navigationDirection = null;
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				fireEditingStopped();
				navigationDirection = null;
			}
		});

		selectionField.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent event) {
				selectionField.setEnabled(true);
				selectionField.requestFocus();
			}
		});
		selectionField.setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
		browseButton = new BrowseButton();
		browseButton.setToolTipText("Browse Existing Category Paths");
		browseButton.addActionListener(e -> showBrowser());

		editorPanel = new JPanel();
		editorPanel.setLayout(new BoxLayout(editorPanel, BoxLayout.X_AXIS));
		editorPanel.add(selectionField);
		editorPanel.add(Box.createHorizontalStrut(5));
		editorPanel.add(browseButton);

		keyListener = new KeyAdapter() {

			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				if (keyCode == KeyEvent.VK_TAB) {
					if (e.isShiftDown()) {
						navigationDirection = NavigationDirection.BACKWARD;
					}
					else {
						navigationDirection = NavigationDirection.FORWARD;
					}

					fireEditingStopped();
					e.consume();
				}
			}
		};
	}

	/**
	 * Retrieve the value in the cell.
	 * @return categoryPath of the selected value from the drop-down
	 */
	@Override
	public CategoryPath getCellEditorValue() {
		return selectionField.getSelectedValue();
	}

	/**
	 * If a path was selected from the drop-down list, it is already 
	 * well-formed and cannot be null. 
	 * @return the selected category path as CategoryPath
	 */
	public CategoryPath getCellEditorValueAsCategoryPath() {
		return selectionField.getSelectedValue();
	}

	/**
	 * Returns the text value of the editor's text field.
	 * @return the text value of the editor's text field.
	 */
	public String getCellEditorValueAsText() {
		return selectionField.getText();
	}

	/**
	 * Returns the component that allows the user to edit.
	 * @return the component that allows the user to edit.
	 */
	public JComponent getEditorComponent() {
		return editorPanel;
	}

	/**
	 * Retrieve the dropdown text field that holds the category path collection.
	 * @return CategoryPath dropdown selection text field object
	 */
	public DropDownSelectionTextField<CategoryPath> getDropDownTextField() {
		return selectionField;
	}

	/**
	 * The browse button which opens a menu with the Category Path collection from the data manager.
	 * @return browseButton
	 */
	public JButton getBrowseButton() {
		return browseButton;
	}

	/**
	 * Sets the initially selected node in the data type tree that the user can choose to
	 * show.
	 *
	 * @param path The path to set
	 */
	public void setDefaultSelectedTreePath(TreePath path) {
		this.initiallySelectedTreePath = path;
	}

	/**
	 * Place focus on the selectionField.
	 */
	public void requestFocus() {
		selectionField.requestFocus();
	}

	/**
	 * Highlights the text of the cell editor.
	 */
	void selectCellEditorValue() {
		selectionField.selectAll();
	}

	/**
	 * Sets the cell editor value as the entered String text.
	 * @param text String input
	 */
	public void setCellEditorValueAsText(String text) {
		selectionField.setText(text);
		navigationDirection = null;
	}

	/**
	 * Sets the value to be edited on this cell editor.
	 *
	 * @param path The data type which is to be edited.
	 */
	public void setCellEditorValue(CategoryPath path) {
		selectionField.setSelectedValue(path);
		navigationDirection = null;
	}

	/**
	 * Adds a document listener to the text field editing component of this editor so that users
	 * can be notified when the text contents of the editor change.
	 * @param listener the listener to add.
	 */
	public void addDocumentListener(DocumentListener listener) {
		selectionField.getDocument().addDocumentListener(listener);
	}

	/**
	 * Removes a previously added document listener.
	 * @param listener the listener to remove.
	 */
	public void removeDocumentListener(DocumentListener listener) {
		selectionField.getDocument().removeDocumentListener(listener);
	}

	/**
	 * Add the provided FocusListener to the selectionField.
	 * @param listener FocusListener
	 */
	public void addFocusListener(FocusListener listener) {
		selectionField.addFocusListener(listener);
	}

	/**
	 * Remove the provided FocusListener from the selectionField.
	 * @param listener FocusListener
	 */
	public void removeFocusListener(FocusListener listener) {
		selectionField.removeFocusListener(listener);
	}

	/**
	 * Toggle Tab key commits an edit. Sets the traversal key enabled field of the selectionField.
	 * @param doesCommit Boolean
	 */
	public void setTabCommitsEdit(boolean doesCommit) {
		selectionField.setFocusTraversalKeysEnabled(!doesCommit);

		removeKeyListener(keyListener); // always remove to prevent multiple additions
		if (doesCommit) {
			addKeyListener(keyListener);
		}
	}

	/**
	 * Returns the direction of the user triggered navigation; null if the user did not trigger
	 * navigation out of this component.
	 * @return the direction
	 */
	public NavigationDirection getNavigationDirection() {
		return navigationDirection;
	}

	private void addKeyListener(KeyListener listener) {
		selectionField.addKeyListener(listener);
	}

	private void removeKeyListener(KeyListener listener) {
		selectionField.removeKeyListener(listener);
	}

	private void showBrowser() {
		CategoryPath path = dataTypeManagerService.getCategoryPath(initiallySelectedTreePath);
		if (path != null) {
			setCellEditorValue(path);
			selectionField.requestFocus();
		}
	}

	/**
	 * Enable or disable the Category Path Text Field. 
	 * @param createStructureByName Boolean 
	 */
	public void setEnabled(boolean createStructureByName) {
		selectionField.setEnabled(createStructureByName);
	}

	/**
	 * Determine whether the Category Path Text Field is enabled. 
	 * @return isEnabled boolean 
	 */
	public boolean isEnabled() {
		return selectionField.isEnabled();
	}

	/**
	 * CategoryPathDropDownSelectionDataModel class handles the display and selection of a 
	 * Category Path.
	 */
	private class CategoryPathDropDownSelectionDataModel
			implements DropDownTextFieldDataModel<CategoryPath> {

		private List<CategoryPath> data;

		private Comparator<Object> searchComparator = new CategoryPathComparator();

		/**
		 * Creates a new instance.
		 * 
		 * @param dataTypeService {@link DataTypeManagerService}
		 */
		public CategoryPathDropDownSelectionDataModel(DataTypeManagerService dataTypeService) {
			data = dataTypeService.getSortedCategoryPathList();
		}

		@Override
		public ListCellRenderer<CategoryPath> getListRenderer() {
			return new CategoryPathDropDownRenderer();
		}

		/**
		 * Description of the CategoryPath is the display text of the path as a string.
		
		 * @param categoryPath CategoryPath 
		 * @return String representation of the Category Path
		 */
		@Override
		public String getDescription(CategoryPath categoryPath) {
			return getDisplayText(categoryPath);
		}

		/**
		 * Retrieve the CategoryPath string representation.
		 * 
		 * @param categoryPath CategoryPath 
		 * @return String representation of the Category Path
		 */
		@Override
		public String getDisplayText(CategoryPath categoryPath) {
			return categoryPath.getPath();
		}

		/**
		 * Support for the filtering mechanism on the collection of Category Paths in the Data Manager.
		 * 
		 * @param searchText String entered text
		 * @return filtered list of Category Paths 
		 */
		@Override
		public List<CategoryPath> getMatchingData(String searchText) {
			if (searchText == null || searchText.length() == 0) {
				return Collections.emptyList();
			}

			char END_CHAR = '\uffff';
			String searchTextStart = searchText;
			String searchTextEnd = searchText + END_CHAR;

			int startIndex = Collections.binarySearch(data, searchTextStart, searchComparator);
			int endIndex = Collections.binarySearch(data, searchTextEnd, searchComparator);

			// the binary search returns a negative, incremented position if there is no match in the
			// list for the given search
			if (startIndex < 0) {
				startIndex = -startIndex - 1;
			}

			if (endIndex < 0) {
				endIndex = -endIndex - 1;
			}

			return data.subList(startIndex, endIndex);
		}

		/**
		 * Identify index of first matching CategoryPath from entered text string.
		 * @param dataCollection list of Category Paths
		 * @param text search string
		 * @return int index of first match
		 */
		@Override
		public int getIndexOfFirstMatchingEntry(List<CategoryPath> dataCollection, String text) {
			int lastPreferredMatchIndex = -1;
			for (int i = 0; i < data.size(); i++) {
				CategoryPath dataType = data.get(i);
				String dataTypeName = dataType.getName();
				dataTypeName = dataTypeName.replaceAll(" ", "");
				if (dataTypeName.equals(text)) {
					// an exact match is the best possible match!
					return i;
				}

				if (dataTypeName.equalsIgnoreCase(text)) {
					// keep going, but remember this location, in case we don't find any more matches
					lastPreferredMatchIndex = i;
				}
				else {
					// we've encountered a non-matching entry--nothing left to search
					return lastPreferredMatchIndex;
				}
			}

			return -1; // we only get here when the list is empty
		}

		private class CategoryPathComparator implements Comparator<Object> {
			@Override
			public int compare(Object o1, Object o2) {
				if (o1 instanceof CategoryPath && o2 instanceof String) {
					CategoryPath path = (CategoryPath) o1;
					return path.getName().compareToIgnoreCase(((String) o2));
				}
				throw new AssertException(
					"CategoryPathCompartor used to compare files against a String key!");
			}
		}

		private class CategoryPathDropDownRenderer extends GListCellRenderer<CategoryPath> {

			@Override
			protected String getItemText(CategoryPath path) {
				return path.getPath();
			}

			@Override
			public Component getListCellRendererComponent(JList<? extends CategoryPath> list,
					CategoryPath value, int index, boolean isSelected, boolean cellHasFocus) {

				super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
				return this;
			}
		}

	}
}
