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
package ghidra.app.plugin.core.bookmark;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;

import docking.*;
import docking.action.KeyBindingData;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GTable;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.GoToService;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.task.TaskMonitor;

public class BookmarkProvider extends ComponentProviderAdapter {
	private static final String BOOKMARK_TYPES_ELEMENT_NAME = "BOOKMARK_TYPES";

	private GhidraTable bookmarkTable;
	private JPanel panel;
	private BookmarkTableModel model;
	private TableModelListener listener;

	private Program program;
	private GhidraThreadedTablePanel<BookmarkRowObject> threadedTablePanel;

	private GhidraTableFilterPanel<BookmarkRowObject> tableFilterPanel;

	BookmarkProvider(PluginTool tool, BookmarkPlugin plugin) {
		super(tool, "Bookmarks", plugin.getName(), ProgramActionContext.class);

		setIcon(BookmarkNavigator.NOTE_ICON);
		addToToolbar();
		setKeyBinding(new KeyBindingData(KeyEvent.VK_B, DockingUtils.CONTROL_KEY_MODIFIER_MASK));

		model = new BookmarkTableModel(tool, null);
		threadedTablePanel = new GhidraThreadedTablePanel<>(model);

		bookmarkTable = threadedTablePanel.getTable();
		bookmarkTable.setAutoLookupColumn(BookmarkTableModel.CATEGORY_COL);

		panel = new JPanel(new BorderLayout());
		panel.add(threadedTablePanel, BorderLayout.CENTER);
		panel.add(createFilterFieldPanel(), BorderLayout.SOUTH);

		adjustTableColumns();

		listener = e -> {
			String subTitle;
			if (model.isFiltered()) {
				subTitle = "(filter matched " + bookmarkTable.getRowCount() + " of " +
					model.getKeyCount() + ")";
			}
			else {
				subTitle = "(" + bookmarkTable.getRowCount() + " bookmarks)";
			}
			setSubTitle(subTitle);
			contextChanged();
		};
		bookmarkTable.getModel().addTableModelListener(listener);

		TableColumn column =
			bookmarkTable.getColumn(bookmarkTable.getColumnName(BookmarkTableModel.CATEGORY_COL));
		CategoryCellEditor editor = new CategoryCellEditor();
		column.setCellEditor(editor);

		setDefaultWindowPosition(WindowPosition.BOTTOM);

		// the listing is 'Core'; below the listing
		setWindowGroup("Core.Bookmarks");
		setIntraGroupPosition(WindowPosition.BOTTOM);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program, bookmarkTable);
	}

	void setGoToService(GoToService goToService) {
		bookmarkTable.installNavigation(goToService, goToService.getDefaultNavigatable());
	}

	private JPanel createFilterFieldPanel() {
		tableFilterPanel = new GhidraTableFilterPanel<>(bookmarkTable, model);
		tableFilterPanel.setToolTipText(
			"Include bookmarks with Categories or Descriptions containing this text.");

		return tableFilterPanel;
	}

	/**
	 * Size the columns such that the interesting ones are wider than the uninteresting columns.
	 */
	private void adjustTableColumns() {
		bookmarkTable.sizeColumnsToFit(-1);
		TableColumn column =
			bookmarkTable.getColumn(bookmarkTable.getColumnName(BookmarkTableModel.COMMENT_COL));
		column.setPreferredWidth(200);
		column =
			bookmarkTable.getColumn(bookmarkTable.getColumnName(BookmarkTableModel.PREVIEW_COL));
		column.setPreferredWidth(150);
		column =
			bookmarkTable.getColumn(bookmarkTable.getColumnName(BookmarkTableModel.CATEGORY_COL));
		column.setPreferredWidth(90);
		column =
			bookmarkTable.getColumn(bookmarkTable.getColumnName(BookmarkTableModel.LOCATION_COL));
		column.setPreferredWidth(90);
	}

	void dispose() {
		bookmarkTable.getModel().removeTableModelListener(listener);
		bookmarkTable.dispose();
		threadedTablePanel.dispose();
		tableFilterPanel.dispose();
		bookmarkTable = null;
		tool = null;
		program = null;
		model = null;
	}

	void reload() {
		if (isVisible()) {
			updateTableModel(program);
		}
	}

	void bookmarkAdded(Bookmark bookmark) {
		if (isVisible()) {
			model.bookmarkAdded(bookmark);
		}
	}

	void bookmarkChanged(Bookmark bookmark) {
		if (isVisible()) {
			model.bookmarkChanged(bookmark);
		}
	}

	void bookmarkRemoved(Bookmark bookmark) {
		if (isVisible()) {
			model.bookmarkRemoved(bookmark);
		}
	}

	void setProgram(Program program) {
		this.program = program;
		if (program == null) {
			updateTableModel(program);
			return;
		}

		if (isVisible()) {
			updateTableModel(program);
		}
	}

	FilterState getFilterState() {
		return model.getFilterState();
	}

	void restoreFilterState(FilterState filterState) {
		model.restoreFilterState(filterState);
		reload();
	}

	public void readConfigState(SaveState saveState) {

		/*
		 	Filter persistence note:  We save the current applied filters when the tool is saved.
		 	This means that filtered 'types' that belong to other open, but not active programs
		 	will not get saved.  Thusly, as the filter state changes between program activations,
		 	the filter state for non-active programs will be lost when the tool closes.  This is
		 	a known issue.  
		 	
		 	Doing it this way prevents the tool's xml from getting bloated with
		 	bookmark types as the years drag on.  To correctly implement the feature, we would have
		 	to write filtered types with enough data to age them off.  We decided at the time 
		 	of writing this note that the more robust persistence mechanism is simply not worth
		 	the functionality it provides.  This is mostly due to the fact that users typically 
		 	are not adding custom bookmark types, which can only be done programmatically.
		 */

		String[] names = saveState.getStrings(BOOKMARK_TYPES_ELEMENT_NAME, null);
		loadBookmarkTypes(names);
		contextChanged();
	}

	private void loadBookmarkTypes(String[] names) {
		if (names == null || names.length == 0) {
			return;
		}

		hideAllTypes();
		for (String bookmarkType : names) {
			showType(bookmarkType);
		}

		reload();
	}

	public void writeConfigState(SaveState saveState) {
		// save the selected filters
		Collection<String> allTypes = model.getAllTypes();
		List<String> showingTypes = new ArrayList<>();
		for (String bookmarkType : allTypes) {
			showingTypes.add(bookmarkType);
		}

		String[] strings = showingTypes.toArray(new String[showingTypes.size()]);
		saveState.putStrings(BOOKMARK_TYPES_ELEMENT_NAME, strings);
	}

	boolean isFiltered() {
		return model.isFiltered();
	}

	boolean hasTypeFilterApplied() {
		return model.hasTypeFilterApplied();
	}

	void setFilterTypes(List<String> filterTypes) {
		hideAllTypes();
		for (String type : filterTypes) {
			showType(type);
		}
		reload();

		// let the user know the tool has changed state and they need to save
		tool.setConfigChanged(true);
	}

	void showType(String type) {
		model.showType(type);
	}

	boolean isShowingType(String type) {
		return model.isShowingType(type);
	}

	void hideAllTypes() {
		model.hideAllTypes();
	}

	GTable getBookmarkTable() {
		return bookmarkTable;
	}

	@Override
	public void componentHidden() {
		updateTableModel(null);
	}

	@Override
	public void componentShown() {
		updateTableModel(program);
	}

	private void updateTableModel(Program newProgram) {
		if (model == null) {
			return; // probably have been disposed
		}

		model.reload(newProgram);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("BookmarkPlugin", "Bookmarks");
	}

	public void typeAdded(String type) {
		if (isVisible()) {
			model.typeAdded();
		}
	}

	void delete() {
		if (program == null) {
			return;
		}

		cancelEdits();

		int[] rows = bookmarkTable.getSelectedRows();
		List<BookmarkRowObject> rowObjects = model.getRowObjects(rows);

		BookmarkRowObjectDeleteCommand cmd = new BookmarkRowObjectDeleteCommand(rowObjects);
		if (rowObjects.size() < 20) {
			tool.execute(cmd, program);
		}
		else {
			tool.executeBackgroundCommand(cmd, program);
		}
	}

	private void cancelEdits() {
		if (bookmarkTable.isEditing()) {
			bookmarkTable.getCellEditor().cancelCellEditing();
		}
	}

	ProgramSelection getBookmarkLocations() {
		return bookmarkTable.getProgramSelection();
	}

	public void repaint() {
		bookmarkTable.repaint();
	}

	GhidraTable getTable() {
		return bookmarkTable;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Class for the Category combo box editor component.
	 * Category list model is refreshed each time cell editor is used.
	 */
	private class CategoryCellEditor extends DefaultCellEditor {
		private GhidraComboBox<String> comboBox;
		private CategoryComboBoxModel comboModel;

		@SuppressWarnings("unchecked")
		CategoryCellEditor() {
			super(new GhidraComboBox<>(new CategoryComboBoxModel()));
			comboBox = (GhidraComboBox<String>) editorComponent;
			comboBox.setEditable(true);
			comboModel = (CategoryComboBoxModel) comboBox.getModel();
			setClickCountToStart(2);
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			int viewIndex = table.convertColumnIndexToView(BookmarkTableModel.TYPE_COL);
			comboModel.refresh((String) table.getValueAt(row, viewIndex));
			return super.getTableCellEditorComponent(table, value, isSelected, row, column);
		}
	}

	/**
	 * Class for the combo box model to hold list of categories.
	 */
	private class CategoryComboBoxModel extends DefaultComboBoxModel<String> {

		void refresh(String typeString) {
			removeAllElements();
			if (typeString != null) {
				BookmarkManager manager = program.getBookmarkManager();
				String[] categories = manager.getCategories(typeString);
				for (String element : categories) {
					addElement(element);
				}
			}
		}

	}

	private static class BookmarkRowObjectDeleteCommand extends BackgroundCommand {
		private List<BookmarkRowObject> bookmarkList;

		public BookmarkRowObjectDeleteCommand(List<BookmarkRowObject> bookmarkList) {
			super("BookMark Delete", true, true, true);
			this.bookmarkList = bookmarkList;
		}

		public boolean doApplyTo(DomainObject obj, TaskMonitor monitor) {
			monitor.initialize(bookmarkList.size());
			BookmarkManager mgr = ((Program) obj).getBookmarkManager();
			for (BookmarkRowObject rowObject : bookmarkList) {
				Bookmark bookmark = mgr.getBookmark(rowObject.getKey());
				mgr.removeBookmark(bookmark);
				monitor.incrementProgress(1);
				if (monitor.isCancelled()) {
					break;
				}
			}
			return true;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			boolean wasEabled = obj.isSendingEvents();
			try {
				obj.setEventsEnabled(false);
				return doApplyTo(obj, monitor);
			}
			finally {
				obj.setEventsEnabled(wasEabled);
			}

		}
	}
}
