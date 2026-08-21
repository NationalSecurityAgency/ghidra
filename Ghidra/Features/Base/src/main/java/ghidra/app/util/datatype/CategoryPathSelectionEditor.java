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

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.help.UnsupportedOperationException;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.*;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.button.BrowseButton;
import docking.widgets.list.GListCellRenderer;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.CategoryPath;

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
		selectionField.setName("CategoryPath");
		selectionField.getAccessibleContext().setAccessibleName("Category");
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

		JPanel browsePanel = buildBrowsePanel();
		editorPanel = new JPanel();
		editorPanel.setLayout(new BoxLayout(editorPanel, BoxLayout.X_AXIS));
		editorPanel.add(selectionField);
		editorPanel.add(browsePanel);

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

	private JPanel buildBrowsePanel() {

		// We override the various sizes to make sure the button does not get too big or too small,
		// which changes depending upon the theme being used.
		JPanel browsePanel = new JPanel() {

			@Override
			public Dimension getPreferredSize() {
				int width = getBestWidth();
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = Math.min(width, preferredSize.width);
				return preferredSize;
			}

			@Override
			public Dimension getMinimumSize() {
				int width = getBestWidth();
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = Math.min(width, preferredSize.width);
				return preferredSize;
			}

			@Override
			public Dimension getMaximumSize() {
				int width = getBestWidth();
				Dimension preferredSize = super.getPreferredSize();
				preferredSize.width = Math.min(width, preferredSize.width);
				return preferredSize;
			}

			private int getBestWidth() {
				Font f = getFont();
				FontMetrics fm = getFontMetrics(f);
				int width = fm.stringWidth(" . . . ");
				return width;
			}
		};

		browsePanel.setLayout(new BorderLayout());
		browsePanel.setOpaque(false);

		// Space the button so that it pops out visually.  This was chosen by trial-and-error and 
		// looks reasonable on all themes.  
		Border empty = BorderFactory.createEmptyBorder(2, 2, 1, 1);
		browsePanel.setBorder(empty);

		browseButton = new BrowseButton();
		browseButton.setToolTipText("Browse Existing Category Paths");
		browseButton.addActionListener(e -> showBrowser());
		browsePanel.add(browseButton);

		return browsePanel;
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
	 * Retrieve the drop-down text field that holds the category path collection.
	 * @return CategoryPath drop-down selection text field object
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

		public CategoryPathDropDownSelectionDataModel(DataTypeManagerService dataTypeService) {
			data = dataTypeService.getSortedCategoryPathList();
		}

		@Override
		public ListCellRenderer<CategoryPath> getListRenderer() {
			return new CategoryPathDropDownRenderer();
		}

		@Override
		public String getDescription(CategoryPath categoryPath) {
			return null;
		}

		@Override
		public String getDisplayText(CategoryPath categoryPath) {
			return categoryPath.getPath();
		}

		@Override
		public List<SearchMode> getSupportedSearchModes() {
			return List.of(SearchMode.CONTAINS, SearchMode.STARTS_WITH, SearchMode.WILDCARD);
		}

		@Override
		public List<CategoryPath> getMatchingData(String searchText) {
			throw new UnsupportedOperationException(
				"Method no longer supported.  Instead, call getMatchingData(String, SearchMode)");
		}

		@Override
		public List<CategoryPath> getMatchingData(String searchText, SearchMode mode) {
			if (StringUtils.isBlank(searchText)) {
				return new ArrayList<>(data);
			}

			if (!getSupportedSearchModes().contains(mode)) {
				throw new IllegalArgumentException("Unsupported SearchMode: " + mode);
			}

			Pattern p = mode.createPattern(searchText);
			boolean startsWith = mode == SearchMode.STARTS_WITH;

			if (startsWith) {
				// update the 'starts with' pattern to allow for optional leading slash, as that is
				// sometimes intuitive for the user to type.
				String pattern = p.pattern();
				String newPattern = "/{0,1}" + pattern;
				p = Pattern.compile(newPattern, Pattern.CASE_INSENSITIVE);
			}

			return getMatchingDataRegex(p, startsWith);
		}

		private List<CategoryPath> getMatchingDataRegex(Pattern p, boolean startsWith) {
			List<CategoryPath> results = new ArrayList<>();
			for (CategoryPath path : data) {
				// use the name for 'startsWith' searches so users can avoid slashes or path data
				String text =
					startsWith ? CategoryPath.DELIMITER_CHAR + path.getName() : path.getPath();
				Matcher m = p.matcher(text);
				if (m.matches()) {
					results.add(path);
				}
			}
			return results;
		}

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
