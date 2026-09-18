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
package ghidra.app.plugin.core.datamgr.tree;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.help.UnsupportedOperationException;
import javax.swing.*;

import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.dnd.GTableDragProvider;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import generic.theme.GIcon;
import ghidra.app.nav.DecoratorPanel;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.actions.*;
import ghidra.app.plugin.core.datamgr.actions.associate.*;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Enum;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * A component provider that shows a table of data types.  For a tree of data types, see the 
 * {@link DataTypesProvider}.
 */
public class DataTypesTableProvider extends ComponentProvider {

	private static final String FILTER_STATE_PREF_KEY =
		DataTypesTableProvider.class.getSimpleName() + ".DtFilterState";

	private static final String SHOW_ONLY_PROGRAM_TYPES_KEY = "SHOW_ONLY_PROGRAM_TYPES";

	private DataTypeManagerPlugin plugin;
	private JComponent component;
	private DataTypesModel model;
	private GTable table;
	private GhidraTableFilterPanel<DataType> filterPanel;
	private DtFilterState filterState = new DtFilterState();

	private DtTableArchiveListener archiveListener;
	private DataTypeManagerChangeListener dtmListener;
	private Program program;

	private ToggleDockingAction showOnlyProgramTypesAction;

	public DataTypesTableProvider(DataTypeManagerPlugin plugin) {
		this(plugin, getDtFilterState(plugin), plugin.getCurrentProgram(), true);
	}

	private DataTypesTableProvider(DataTypeManagerPlugin plugin, DtFilterState filterState,
			Program program, boolean isConnected) {

		super(plugin.getTool(), "Data Types Table", plugin.getName());
		this.plugin = plugin;
		this.filterState = filterState;
		this.program = program;

		if (!isConnected) {
			setTransient();
		}

		createActions();

		build();

		setDefaultWindowPosition(WindowPosition.WINDOW);
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Data_Types_Table"));

		addToTool();

		new DtTableDragProvider(table, model);

		updateTitle();

		ArchiveManager archiveManager = plugin.getArchiveManager();
		archiveListener = new DtTableArchiveListener();
		archiveManager.addArchiveManagerListener(archiveListener);

		dtmListener = new DtTableDtmChangeListener();
		plugin.addDataTypeManagerChangeListener(dtmListener);

		if (!isConnected) {
			plugin.addDisconnectedTableProvider(this);
		}
	}

	private static DtFilterState getDtFilterState(DataTypeManagerPlugin plugin) {

		PreferenceState preferenceState = getPreferenceState(plugin);
		if (preferenceState != null) {
			DtFilterState filterState = new DtFilterState();
			filterState.restore(preferenceState);
			return filterState;
		}

		// use the tree's current filter state as a default
		return plugin.getTreeFilterState();
	}

	private static PreferenceState getPreferenceState(DataTypeManagerPlugin plugin) {
		PluginTool tool = plugin.getTool();
		DockingWindowManager dwm = tool.getWindowManager();
		return dwm.getPreferenceState(FILTER_STATE_PREF_KEY);
	}

	private void saveDtFilterState() {
		PluginTool tool = plugin.getTool();
		DockingWindowManager dwm = tool.getWindowManager();
		PreferenceState preferenceState = new PreferenceState();
		filterState.save(preferenceState);

		preferenceState.putBoolean(SHOW_ONLY_PROGRAM_TYPES_KEY,
			showOnlyProgramTypesAction.isSelected());

		dwm.putPreferenceState(FILTER_STATE_PREF_KEY, preferenceState);
	}

	public void programActivated(Program newProgram) {
		if (isTransient()) {
			throw new UnsupportedOperationException("Cannot set program on snapshot table");
		}
		this.program = newProgram;
		updateTitle();
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public void closeComponent() {

		// we are transient, so cleanup when closed
		if (isTransient()) {
			dispose();
		}
		else {
			model.clear();
		}

		super.closeComponent();
	}

	@Override
	public void componentShown() {
		if (!isTransient()) {
			model.reload();
		}
	}

	private void dispose() {

		if (isTransient()) {
			plugin.removeDisconnectedTableProvider(this);
		}

		ArchiveManager archiveManager = plugin.getArchiveManager();
		archiveManager.removeArchiveManagerListener(archiveListener);
		plugin.removeDataTypeManagerChangeListener(dtmListener);

		// save the type filter and the table filter
		saveDtFilterState();
		filterPanel.dispose();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	public GTable getTable() {
		return table;
	}

	public ThreadedTableModel<DataType, Object> getTableModel() {
		return model;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		List<DataType> types = filterPanel.getSelectedItems();
		return new DataTypeTableContext(this, types);
	}

	private void updateTitle() {
		String title = getName();
		if (isTransient()) {
			title = "[" + title + "]";
			setTabText(title);
		}

		setTitle(title);
		updateSubTitle();
	}

	private void updateSubTitle() {
		String programText = "";
		if (program != null) {
			programText = " - " + program.getName();
		}
		setSubTitle(filterPanel.getRowCount() + " types" + programText);
	}

	private void build() {

		JPanel panel = new JPanel(new BorderLayout());

		model = new DataTypesModel(plugin.getTool());
		GhidraThreadedTablePanel<DataType> tablePanel =
			new GhidraThreadedTablePanel<>(model, 250);
		table = tablePanel.getTable();
		table.setPreferredScrollableViewportSize(new Dimension(800, 400));

		filterPanel = new GhidraTableFilterPanel<>(table, model);

		String namePrefix = "Data Types";
		table.setAccessibleNamePrefix(namePrefix);
		filterPanel.setAccessibleNamePrefix(namePrefix);

		model.addThreadedTableModelListener(new ThreadedTableModelListener() {

			@Override
			public void loadingStarted() {
				// stub
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				updateSubTitle();
			}

			@Override
			public void loadPending() {
				// stub
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2) {
					return;
				}

				DataType dt = filterPanel.getSelectedItem();
				if (dt != null) {
					plugin.edit(dt);
				}
			}
		});

		panel.add(tablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		component = new DecoratorPanel(panel, !isTransient());
	}

	private void setFilterState(DtFilterState filterState) {
		this.filterState = filterState;
		model.reload();
	}

	private void createActions() {

		// 
		// Toolbar actions
		//
		addLocalAction(new DtTableFilterAction(plugin));

		// Clone
		new ActionBuilder("Data Types Table Snapshot", plugin.getName())
				.toolBarIcon(new GIcon("icon.provider.clone"))
				.onAction(this::clone)
				.buildAndInstallLocal(this);

		// program types filter
		showOnlyProgramTypesAction =
			new ToggleActionBuilder("Program Types Filter", plugin.getName())
					.toolBarIcon(new GIcon("icon.plugin.datatypes.archive.program.closed"))
					.toolBarGroup("filters")
					.selected(false)
					.onAction(c -> reload())
					.buildAndInstallLocal(this);

		PreferenceState preferenceState = getPreferenceState(plugin);
		if (preferenceState != null) {
			boolean onlyProgram = preferenceState.getBoolean(SHOW_ONLY_PROGRAM_TYPES_KEY, false);
			showOnlyProgramTypesAction.setSelected(onlyProgram);
		}

		// Show in Tree / Select in Tree (select all items)
		new ActionBuilder("Select Data Types in Tree", plugin.getName())
				.popupMenuPath("Select in Tree")
				.popupMenuGroup("ZVeryLast")
				.enabledWhen(a -> table.getSelectedRowCount() > 0)
				.onAction(a -> {
					List<DataType> types = filterPanel.getSelectedItems();
					plugin.setDataTypeSelected(types);
				})
				.buildAndInstallLocal(this);

		//
		// Popup Actions
		//
		// Edit group
		addLocalAction(new EditAction(plugin));
		addLocalAction(new CompareDataTypesAction(plugin));
		addLocalAction(new ReplaceDataTypeAction(plugin));

		// ZVeryLast group
		addLocalAction(new FindReferencesToDataTypeAction(plugin)); // DataType

		// Synchronize
		addLocalAction(new AssociateDataTypeAction(plugin));
		addLocalAction(new CommitSingleDataTypeAction(plugin));
		addLocalAction(new UpdateSingleDataTypeAction(plugin));
		addLocalAction(new RevertDataTypeAction(plugin));
		addLocalAction(new DisassociateDataTypeAction(plugin));

	}

	private void clone(ActionContext context) {
		DtFilterState newFilterState = filterState.copy();
		DataTypesTableProvider newProvider =
			new DataTypesTableProvider(plugin, newFilterState, program, false);

		filterPanel.transferSettings(newProvider.filterPanel);

		newProvider.showOnlyProgramTypesAction.setSelected(showOnlyProgramTypesAction.isSelected());

		newProvider.setVisible(true);
	}

	private void reload() {
		// Add a listener to restore the selected types after the table has been reloaded
		List<DataType> types = filterPanel.getSelectedItems();
		model.addInitialLoadListener(c -> {
			List<DataType> updatedTypes = getUpdatedTypes(types);
			filterPanel.setSelectedItems(updatedTypes);
			table.scrollToSelectedRow();
		});

		model.reload();
	}

	/**
	 * Uses the given types to find the equivalent type after a reload operation. 
	 * @param types the old types
	 * @return the equivalent new types
	 */
	private List<DataType> getUpdatedTypes(List<DataType> types) {

		List<DataType> newTypes = new ArrayList<>();
		for (DataType dt : types) {
			DataTypeManager dtm = dt.getDataTypeManager();
			DataType newType = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
			newTypes.add(newType);
		}

		return newTypes;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class DtTableDragProvider extends GTableDragProvider<DataType> {

		public DtTableDragProvider(GTable table, RowObjectTableModel<DataType> model) {
			super(table, model);
		}

		@Override
		protected int getDragActions() {
			return DnDConstants.ACTION_COPY_OR_MOVE;
		}

		@Override
		protected Transferable createDragTransferable(List<DataType> items) {
			return new DataTypeTableTransferable(items);
		}

		private class DataTypeTableTransferable implements Transferable {

			private static final DataFlavor[] FLAVORS = new DataFlavor[] {
				DataTypeTransferable.localDataTypeFlavor,
				DataTypeTransferable.localDataTypeListFlavor
			};

			private List<DataType> types;

			DataTypeTableTransferable(List<DataType> types) {
				this.types = types;
			}

			@Override
			public DataFlavor[] getTransferDataFlavors() {
				return FLAVORS;
			}

			@Override
			public boolean isDataFlavorSupported(DataFlavor flavor) {
				for (DataFlavor f : FLAVORS) {
					if (f.equals(flavor)) {
						return true;
					}
				}
				return false;
			}

			@Override
			public Object getTransferData(DataFlavor flavor)
					throws UnsupportedFlavorException, IOException {

				if (flavor.equals(DataTypeTransferable.localDataTypeFlavor)) {
					return types.get(0);
				}
				else if (flavor.equals(DataTypeTransferable.localDataTypeListFlavor)) {
					return Collections.unmodifiableList(types);
				}

				throw new UnsupportedFlavorException(flavor);
			}
		}
	}

	private class DtTableFilterAction extends DockingAction {

		public DtTableFilterAction(DataTypeManagerPlugin plugin) {
			super("Show Filter", plugin.getName());
			setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON, "filters"));
			setDescription("Shows the Data Types filter");
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			ComponentProvider provider = context.getComponentProvider();
			return provider == DataTypesTableProvider.this;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DtFilterState currentFilterState = filterState;
			DtFilterDialog dialog = new DtFilterDialog(currentFilterState);
			plugin.getTool().showDialog(dialog, getComponent());

			if (dialog.isCancelled()) {
				return;
			}

			DtFilterState newFilterState = dialog.getFilterState();
			if (currentFilterState.equals(newFilterState)) {
				return;
			}

			setFilterState(newFilterState);
		}

	}

	private class DtTableArchiveListener implements ArchiveManagerListener {

		@Override
		public void archiveOpened(PersistentDataTypeArchive archive) {
			reload();
		}

		@Override
		public void archiveClosed(PersistentDataTypeArchive archive) {
			reload();
		}

		@Override
		public void programOpened(Program p) {
			reload();
		}

		@Override
		public void programClosed(Program p) {
			reload();
		}

		@Override
		public void invalidArchiveAdded(InvalidArchive invalidArchive) {
			// stub
		}

		@Override
		public void invalidArchiveRemoved(InvalidArchive invalidArchive) {
			// stub
		}

		@Override
		public void stateChanged(DataTypeStore dataTypeStore) {
			table.repaint();
		}
	}

	private class DtTableDtmChangeListener implements DataTypeManagerChangeListener {
		@Override
		public void sourceArchiveChanged(DataTypeManager dataTypeManager,
				SourceArchive sourceArchive) {
			table.repaint();
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dataTypeManager,
				SourceArchive sourceArchive) {
			reload();
		}

		@Override
		public void restored(DataTypeManager dataTypeManager) {
			reload();
		}

		@Override
		public void programArchitectureChanged(DataTypeManager dataTypeManager) {
			// stub
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path,
				boolean isFavorite) {
			// stub
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			table.repaint();
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			table.repaint();
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			DataType dt = dtm.getDataType(path);
			model.removeObject(dt);
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			table.repaint();
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			table.repaint();
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			DataType dt = dtm.getDataType(path);
			model.addObject(dt);
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			// stub
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			// stub
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			table.repaint();
		}

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			// stub
		}
	}

	private class DataTypesModel extends ThreadedTableModel<DataType, Object> {

		protected DataTypesModel(ServiceProvider serviceProvider) {
			super("Data Types", serviceProvider);
		}

		public void clear() {
			// this will work if this provider is not visible when doLoad() is called
			model.reload();
		}

		@Override
		public void addObject(DataType dt) {
			if (filterState.passesFilters(dt)) {
				super.addObject(dt);
			}
		}

		@Override
		protected void doLoad(Accumulator<DataType> accumulator, TaskMonitor monitor)
				throws CancelledException {

			if (!isVisible()) {
				return;
			}

			if (program == null) {
				return; // the tool is initializing
			}

			ProgramBasedDataTypeManager programDtm = program.getDataTypeManager();
			loadTypes(programDtm, accumulator, monitor);

			if (showOnlyProgramTypesAction.isSelected()) {
				return;
			}

			ArchiveManager archiveManager = plugin.getArchiveManager();
			List<PersistentDataTypeArchive> archives = archiveManager.getOpenArchives();
			for (PersistentDataTypeArchive archive : archives) {
				DataTypeManager dtm = archive.getDataTypeManager();
				if (dtm instanceof ProgramBasedDataTypeManager) {
					continue;
				}

				loadTypes(dtm, accumulator, monitor);
			}
		}

		private void loadTypes(DataTypeManager dtm, Accumulator<DataType> accumulator,
				TaskMonitor monitor) throws CancelledException {

			Iterator<DataType> it = dtm.getAllDataTypes();
			while (it.hasNext()) {
				monitor.checkCancelled();

				DataType dt = it.next();
				if (filterState.passesFilters(dt)) {
					accumulator.add(dt);
				}
			}
		}

		@Override
		protected TableColumnDescriptor<DataType> createTableColumnDescriptor() {

			TableColumnDescriptor<DataType> descriptor = new TableColumnDescriptor<>();

			descriptor.addVisibleColumn(new TypeColumn());
			descriptor.addVisibleColumn(new NameColumn());
			descriptor.addVisibleColumn(new LengthColumn());
			descriptor.addVisibleColumn(new CategoryPathColumn());
			descriptor.addVisibleColumn(new ArchiveColumn());
			descriptor.addVisibleColumn(new SyncColumn());

			descriptor.addHiddenColumn(new LastChangedColumn());
			descriptor.addHiddenColumn(new CommentColumn());
			descriptor.addHiddenColumn(new PackingColumn());
			descriptor.addHiddenColumn(new AlignmentColumn());
			descriptor.addHiddenColumn(new AlignmentLengthColumn());
			descriptor.addHiddenColumn(new SourceColumn());

			return descriptor;
		}

		@Override
		public Program getDataSource() {
			return null;
		}

		private class NameColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, String> {

			@Override
			public String getColumnName() {
				return "Name";
			}

			@Override
			public String getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				return rowObject.getName();
			}
		}

		private class LengthColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, Integer> {

			@Override
			public String getColumnName() {
				return "Length";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 40;
			}

			@Override
			public Integer getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				int len = rowObject.getLength();
				if (len < 0) {
					return null;
				}
				return len;
			}
		}

		private class CategoryPathColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, String> {

			@Override
			public String getColumnName() {
				return "Path";
			}

			@Override
			public String getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				return rowObject.getCategoryPath().toString();
			}
		}

		private class LastChangedColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, Date> {

			private DateRenderer renderer = new DateRenderer();

			@Override
			public String getColumnName() {
				return "Modified";
			}

			@Override
			public Date getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				long time = rowObject.getLastChangeTime();
				if (time == 0) {
					return null;
				}
				return new Date(time);
			}

			@Override
			public GColumnRenderer<Date> getColumnRenderer() {
				return renderer;
			}

			private class DateRenderer extends AbstractGColumnRenderer<Date> {
				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					JLabel label = (JLabel) super.getTableCellRendererComponent(data);
					Date date = (Date) data.getValue();
					if (date == null) {
						return label;
					}

					String formatted = DateUtils.formatDate(date);
					label.setText(formatted);
					return label;
				}

				@Override
				public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
					// not sure about this: it could be USE_COLUMN_CONSTRAINTS_ONLY, but then the text
					// filter would not match the formatted date.  This allows for both.
					return ColumnConstraintFilterMode.ALLOW_ALL_FILTERS;
				}

				@Override
				public String getFilterString(Date t, Settings settings) {
					String formatted = DateUtils.formatDate(t);
					return formatted;
				}
			}
		}

		private class SourceColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, String> {

			@Override
			public String getColumnName() {
				return "Source";
			}

			@Override
			public String getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				SourceArchive source = rowObject.getSourceArchive();
				if (source != null) {
					return source.getName();
				}
				return null;
			}

		}

		private class TypeColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, MyIconWrapper> {

			// use a renderer to get filtering by icon text (e.g., Function, Structure, etc)
			private IconRenderer renderer = new IconRenderer();

			@Override
			public String getColumnName() {
				return "Icon";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 30;
			}

			@Override
			public MyIconWrapper getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {

				Icon icon = DataTypeUtils.getIconForDataType(rowObject, false);
				String description = DataTypeUtils.getIconTextForDataType(rowObject);

				if (description == null) {
					// Assume a primitive type; not sure of the best text for this.  This text 
					// allows the user to filter on this column.
					description = "Built-in";
				}

				return new MyIconWrapper(icon, description);
			}

			@Override
			public GColumnRenderer<MyIconWrapper> getColumnRenderer() {
				return renderer;
			}

			private class IconRenderer extends AbstractGColumnRenderer<MyIconWrapper> {

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					MyIconWrapper iconWrapper = (MyIconWrapper) data.getValue();
					Icon icon = iconWrapper.icon();

					JLabel label = (JLabel) super.getTableCellRendererComponent(data);
					label.setText("");
					label.setIcon(icon);
					label.setToolTipText(iconWrapper.desription());
					return label;
				}

				@Override
				protected String getAccessibleCellValue(GTableCellRenderingData data, String text) {
					MyIconWrapper iconWrapper = (MyIconWrapper) data.getValue();
					return iconWrapper.desription();
				}

				@Override
				public String getFilterString(MyIconWrapper t, Settings settings) {
					return t.desription();
				}

			}
		}

		private record MyIconWrapper(Icon icon, String desription) {}

		private class ArchiveColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, String> {

			@Override
			public String getColumnName() {
				return "Archive";
			}

			@Override
			public String getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				return rowObject.getDataTypeManager().getName();
			}
		}

		private class CommentColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, String> {

			@Override
			public String getColumnName() {
				return "Comment";
			}

			@Override
			public String getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {

				if (rowObject instanceof Structure s) {
					return s.getDescription();
				}
				else if (rowObject instanceof FunctionDefinition fd) {
					return fd.getComment();
				}
				else if (rowObject instanceof Enum e) {
					return e.getDescription();
				}

				return null;
			}
		}

		private class PackingColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, Integer> {

			@Override
			public String getColumnName() {
				return "Packing";
			}

			@Override
			public Integer getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				if (rowObject instanceof Composite c) {
					if (c.hasExplicitPackingValue()) {
						return c.getExplicitPackingValue();
					}
				}
				return null;
			}
		}

		private class AlignmentColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, Integer> {

			@Override
			public String getColumnName() {
				return "Alignment";
			}

			@Override
			public Integer getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				if (rowObject instanceof Composite c) {
					return c.getAlignment();
				}
				return null;
			}
		}

		private class AlignmentLengthColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, Integer> {

			@Override
			public String getColumnName() {
				return "Aligned Length";
			}

			@Override
			public Integer getValue(DataType rowObject, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {
				int len = rowObject.getAlignedLength();
				if (len < 0) {
					return null;
				}
				return len;
			}

		}

		private class SyncColumn
				extends AbstractProgramBasedDynamicTableColumn<DataType, DataTypeSyncState> {

			// Note: these also live in the DataTypeArchiveGTree
			private static Icon LOCAL_DELTA_ICON =
				new GIcon("icon.plugin.datatypes.tree.change.local");
			private static Icon SOURCE_DELTA_ICON =
				new GIcon("icon.plugin.datatypes.tree.change.source");
			private static Icon CONFLICT_ICON = new GIcon("icon.plugin.datatypes.tree.conflict");
			private static Icon MISSING_ICON = new GIcon("icon.plugin.datatypes.tree.missing");

			private SyncRenderer renderer = new SyncRenderer();

			@Override
			public String getColumnName() {
				return "Sync";
			}

			@Override
			public String getColumnDescription() {
				return "The sync status for 'associated' types";
			}

			@Override
			public int getColumnPreferredWidth() {
				return 30;
			}

			@Override
			public GColumnRenderer<DataTypeSyncState> getColumnRenderer() {
				return renderer;
			}

			@Override
			public DataTypeSyncState getValue(DataType dt, Settings settings, Program data,
					ServiceProvider sp) throws IllegalArgumentException {

				SourceArchive sourceArchive = dt.getSourceArchive();
				if (!hasOtherSourceArchive(dt, sourceArchive)) {
					return null;
				}

				ArchiveManager archiveManager = plugin.getArchiveManager();
				DataTypeSyncState status = DataTypeSynchronizer.getSyncStatus(archiveManager, dt);
				return status;
			}

			private boolean hasOtherSourceArchive(DataType dataType, SourceArchive sourceArchive) {
				if (sourceArchive == null) {
					return false;
				}

				if (sourceArchive.getArchiveType().isBuiltIn()) {
					return false;
				}

				UniversalID localID = dataType.getDataTypeManager().getUniversalID();
				return !sourceArchive.getSourceArchiveID().equals(localID);
			}

			private class SyncRenderer extends AbstractGColumnRenderer<DataTypeSyncState> {

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					JLabel label = (JLabel) super.getTableCellRendererComponent(data);
					label.setText("");
					label.setHorizontalAlignment(SwingConstants.CENTER);

					Object value = data.getValue();
					DataTypeSyncState status = (DataTypeSyncState) value;
					StatusDecoration decoration = getStatusDecoration(status);
					if (decoration != null) {
						label.setIcon(decoration.icon());
						label.setToolTipText(decoration.description());
					}
					else {
						label.setIcon(null);
						label.setToolTipText(null);
					}

					return label;
				}

				private StatusDecoration getStatusDecoration(DataTypeSyncState state) {
					if (state == null) {
						return null;
					}
					switch (state) {
						case CONFLICT:
							return new StatusDecoration(CONFLICT_ICON,
								"Type conflicts with source archive");
						case UPDATE:
							return new StatusDecoration(SOURCE_DELTA_ICON,
								"Type updated in source archive");
						case COMMIT:
							return new StatusDecoration(LOCAL_DELTA_ICON,
								"Changes to be commited to source archive");
						case ORPHAN:
							return new StatusDecoration(MISSING_ICON,
								"Orphaned from source archive");
						case UNKNOWN:
						case IN_SYNC:
						default:
							return null;
					}
				}

				@Override
				public String getFilterString(DataTypeSyncState t, Settings settings) {
					return t.toString();
				}

				private record StatusDecoration(Icon icon, String description) {}
			}
		}
	}

}
