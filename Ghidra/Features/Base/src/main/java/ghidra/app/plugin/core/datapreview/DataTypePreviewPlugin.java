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
package ghidra.app.plugin.core.datapreview;

import java.awt.Component;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.awt.event.*;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.JScrollPane;

import docking.ActionContext;
import docking.action.*;
import docking.dnd.DropTgtAdapter;
import docking.dnd.Droppable;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.QueryData;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.BytesFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;
import util.CollectionUtils;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Data Type Preview Plugin",
	description = "This plugin provides a preview of bytes at an address based on data types " +
		"that you choose to view."
)
//@formatter:on
public class DataTypePreviewPlugin extends ProgramPlugin {

	private static final String ROOT_NAME = "DataTypePreviewer";

	private DTPPComponentProvider provider;
	private DTPPTableModel model;
	private DTPPTable table;
	private DTPPScrollPane component;
	private Address currentAddress;
	private GoToService goToService;
	private DockingAction addAction;
	private DockingAction deleteAction;
	private DataTypeManager dataTypeManager;
	private Program activeProgram;

	private SwingUpdateManager updateManager = new SwingUpdateManager(650, () -> updatePreview());

	public DataTypePreviewPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	DTPPTableModel getTableModel() {
		return model;
	}

	GoToService getGoToService() {
		return goToService;
	}

	DTPPComponentProvider getProvider() {
		return provider;
	}

	@Override
	protected void init() {
		super.init();

		goToService = tool.getService(GoToService.class);

		model = new DTPPTableModel();
		table = new DTPPTable(model);
		component = new DTPPScrollPane(table);
		dataTypeManager = createLayeredDataTypeManager();

		addDataType(new ByteDataType());
		addDataType(new WordDataType());
		addDataType(new DWordDataType());
		addDataType(new QWordDataType());
		addDataType(new FloatDataType());
		addDataType(new DoubleDataType());
		addDataType(new CharDataType());
		addDataType(new TerminatedStringDataType());
		addDataType(new TerminatedUnicodeDataType());

		provider = new DTPPComponentProvider();
		tool.addComponentProvider(provider, false);

		createActions();
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == GoToService.class) {
			goToService = null;
		}
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == GoToService.class) {
			goToService = (GoToService) service;
		}
	}

	@Override
	protected void dispose() {
		updateManager.dispose();
		deleteAction.dispose();
		if (provider != null) {
			tool.removeComponentProvider(provider);
			provider = null;
		}

		updateManager.dispose();
		updateManager = null;
		table.dispose();
		if (dataTypeManager != null) {
			dataTypeManager.close();
		}
		super.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		super.programActivated(program);
		activeProgram = program;
		updateModel();
	}

	private List<DataTypePath> getModelDataTypePaths() {
		// retain order as they currently exist within model
		List<DataTypePath> list = new ArrayList<>();
		for (Preview preview : model.getModelData()) {
			if (preview instanceof DataTypePreview) {
				list.add(preview.getDataType().getDataTypePath());
			}
			else if (preview instanceof DataTypeComponentPreview) {
				DataTypeComponentPreview componentPreview = (DataTypeComponentPreview) preview;
				if (componentPreview.getParent() == null) {
					list.add(preview.getDataType().getDataTypePath());
				}
			}
		}
		return list;
	}

	private void updateModel() {

		DataTypeManager newDtm = createLayeredDataTypeManager();

		int transactionId = newDtm.startTransaction("add datatypes");
		try {
			Iterator<DataType> allDataTypes = dataTypeManager.getAllDataTypes();
			while (allDataTypes.hasNext()) {
				newDtm.resolve(allDataTypes.next(), null);
			}
		}
		finally {
			newDtm.endTransaction(transactionId, true);
		}

		// NOTE: data types do not respond to switching the data organization object
		// since this is cached internal to the data type at time of construction.
		// We must purge old datatypes and have them re-instantiated by the 
		// datatype manager
		List<DataTypePath> dtPaths = getModelDataTypePaths();
		model.removeAll();

		DataTypeManager oldDtm = dataTypeManager;
		dataTypeManager = newDtm;
		oldDtm.close();

		for (DataTypePath dtPath : dtPaths) {
			DataType dataType = dataTypeManager.getDataType(dtPath);
			if (dataType != null) {
				model.add(dataType);
			}
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		super.programDeactivated(program);
		activeProgram = null;
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		if (loc == null) {
			return;
		}

		if (loc instanceof BytesFieldLocation) {
			currentAddress = ((BytesFieldLocation) loc).getAddressForByte();
		}
		else {
			currentAddress = loc.getByteAddress();
		}

		updateManager.update();
	}

	private void updatePreview() {
		if (currentAddress == null) {
			return;
		}

		if (provider.isVisible()) {
			model.fireTableDataChanged();
			updateTitle();
		}
	}

	private void updateTitle() {
		if (currentAddress != null) {
			provider.setSubTitle(" at " + currentAddress);
		}
		else {
			provider.setSubTitle(null);
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String[] names = saveState.getNames();
		if (CollectionUtils.isBlank(names)) {
			return;
		}

		BuiltInDataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();
		try {
			for (String element : names) {
				String path = saveState.getString(element, null);
				if (path == null) {
					continue;
				}

				DataType dt = builtInMgr.getDataType(new CategoryPath(path), element);
				addDataType(dt);
			}
		}
		finally {
			builtInMgr.close();
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		Iterator<Preview> iter = model.iterator();
		while (iter.hasNext()) {
			Preview preview = iter.next();
			DataType dt = preview.getDataType();
			saveState.putString(dt.getName(), dt.getCategoryPath().getPath());
		}
	}

	private void setActionEnabled(boolean enabled) {
		deleteAction.setEnabled(enabled);
	}

	private void createActions() {
		addAction = new DockingAction("Add", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				add();
			}
		};
		addAction.setPopupMenuData(new MenuData(new String[] { "Add" }));
		addAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/Plus.png")));
		addAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_PLUS, 0));

		addAction.setDescription("Add Datatypes");
		addAction.setEnabled(true);
		tool.addLocalAction(provider, addAction);

		deleteAction = new DockingAction("Delete", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				delete();
			}
		};
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }));
		deleteAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/edit-delete.png")));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		deleteAction.setDescription("Delete Selected Datatypes");
		deleteAction.setEnabled(false);
		tool.addLocalAction(provider, deleteAction);
	}

	private void add() {
		DataTypeManager dtm = null;
		if (activeProgram != null) {
			dtm = activeProgram.getDataTypeManager();
		}
		DataTypeSelectionDialog d = new DataTypeSelectionDialog(tool, dtm, Integer.MAX_VALUE,
			AllowedDataTypes.STRINGS_AND_FIXED_LENGTH);
		tool.showDialog(d, provider);
		DataType dt = d.getUserChosenDataType();
		addDataType(dt);
	}

	void addDataType(DataType dt) {

		if (dt == null || model.contains(dt)) {
			return;
		}

		int transactionID = dataTypeManager.startTransaction("Add dataType");
		try {
			DataType resolvedDt = dataTypeManager.resolve(dt, null);
			model.add(resolvedDt);
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	private void removeDataType(DataType dt) {
		int transactionID = dataTypeManager.startTransaction("Remove dataType");
		try {
			model.removeAll(dt);

			// Note: do not do this, as there may be user-added composites that are based on 
			//       the type being removed.  For now, let the 'fake' DTM grow forever (this should
			//       never become a problem).
			// dataTypeManager.remove(dt, null);
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	private void delete() {
		int[] rows = table.getSelectedRows();
		if (rows.length == 0) {
			return;
		}
		Preview[] previews = model.getPreviews(rows);
		for (Preview element : previews) {
			removeDataType(element.getDataType());
		}
		if (model.getRowCount() > 0) {
			if (model.getRowCount() > rows[0]) {
				table.setRowSelectionInterval(rows[0], rows[0]);
			}
			else {
				table.setRowSelectionInterval(model.getRowCount() - 1, model.getRowCount() - 1);
			}
		}
		setActionEnabled(model.getRowCount() > 0);
	}

	private class DTPPComponentProvider extends ComponentProviderAdapter {
		public DTPPComponentProvider() {
			super(DataTypePreviewPlugin.this.getTool(), "Data Type Preview",
				DataTypePreviewPlugin.this.getName());
			setHelpLocation(new HelpLocation(DataTypePreviewPlugin.this.getName(),
				DataTypePreviewPlugin.this.getName()));
		}

		@Override
		public void componentShown() {
			updateTitle();
		}

		@Override
		public JComponent getComponent() {
			return component;
		}
	}

	private class DTPPDroppable implements Droppable {
		private DataFlavor[] acceptableFlavors;
		private DropTgtAdapter dropTargetAdapter;
		private Component dropTargetComponent;

		DTPPDroppable(Component dropTarget) {
			dropTargetComponent = dropTarget;
			setUpDrop();
		}

		@Override
		public boolean isDropOk(DropTargetDragEvent e) {
			return true;
		}

		@Override
		public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
			// don't care
		}

		@Override
		public void undoDragUnderFeedback() {
			// don't care
		}

		@Override
		public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
			if (obj instanceof DataType) {
				DataType dt = (DataType) obj;
				addDataType(dt);
			}
		}

		private void setUpDrop() {
			acceptableFlavors = new DataFlavor[] { DataTypeTransferable.localDataTypeFlavor,
				DataTypeTransferable.localBuiltinDataTypeFlavor };

			dropTargetAdapter =
				new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);

			DropTarget dropTarget = new DropTarget(dropTargetComponent,
				DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
			dropTarget.setActive(true);
		}
	}

	private class DTPPScrollPane extends JScrollPane {
		private static final long serialVersionUID = 1L;

		DTPPScrollPane(Component view) {
			super(view);
			new DTPPDroppable(this);
		}
	}

	private class DTPPTable extends GhidraTable {
		private static final long serialVersionUID = 1L;

		DTPPTable(DTPPTableModel model) {
			super(model);
			addMouseListener(new DTPPMouseListener());
			new DTPPDroppable(this);
		}

		void handleTableSelection() {
			int selectedRow = table.getSelectedRow();
			setActionEnabled(selectedRow >= 0);
		}
	}

	private class DTPPMouseListener extends MouseAdapter {
		@Override
		public void mouseReleased(MouseEvent e) {
			if (e.getButton() == MouseEvent.BUTTON1 && e.getClickCount() == 2) {
				int row = table.getSelectedRow();
				String queryString = model.getPreviewAt(row);
				if (queryString == null) {
					return;
				}

				if (goToService == null) {
					return;
				}

				goToService.goToQuery(currentAddress, new QueryData(queryString, false), null,
					TaskMonitor.DUMMY);
			}
			table.handleTableSelection();
		}
	}

	/*for testing*/ class DTPPTableModel extends AbstractSortedTableModel<Preview> {
		final static int NAME_COL = 0;
		final static int PREVIEW_COL = 1;

		private List<Preview> data = new ArrayList<>();

		String getPreviewAt(int row) {
			if (currentProgram == null) {
				return null;
			}
			Preview p = data.get(row);
			return p.getPreview(currentProgram.getMemory(), currentAddress);
		}

		Preview[] getPreviews(int[] rows) {
			Preview[] previews = new Preview[rows.length];
			for (int i = 0; i < rows.length; i++) {
				previews[i] = data.get(rows[i]);
			}
			return previews;
		}

		Iterator<Preview> iterator() {
			return data.iterator();
		}

		void add(DataType dt) {
			if (!isValid(dt)) {
				return;
			}
			if (contains(dt)) {
				tool.setStatusInfo("Datatype \"" + dt.getName() + "\" already exists.");
				return;
			}
			if (dt instanceof Composite) {
				add((Composite) dt, null);
			}
			else {
				data.add(new DataTypePreview(dt));
			}
			fireTableDataChanged();
		}

		private void add(Composite c, DataTypeComponentPreview parent) {
			DataTypeComponent[] comps = c.getDefinedComponents();
			for (DataTypeComponent element : comps) {
				DataTypeComponentPreview preview = new DataTypeComponentPreview(c, element);
				preview.setParent(parent);
				DataType dataType = element.getDataType();
				if (dataType instanceof Composite) {
					add((Composite) element.getDataType(), preview);
				}
				else {
					data.add(preview);
				}
			}
		}

		void remove(int row) {
			data.remove(row);
			fireTableRowsDeleted(row, row);
		}

		void removeAll() {
			if (data.isEmpty()) {
				return;
			}
			data.clear();
			fireTableDataChanged();
		}

		boolean removeAll(DataType deletedDataType) {
			boolean removed = false;
			ArrayList<Preview> clone = new ArrayList<>(data);
			Iterator<Preview> iter = clone.iterator();
			while (iter.hasNext()) {
				Object obj = iter.next();
				Preview preview = (Preview) obj;
				if (preview.getDataType().equals(deletedDataType)) {
					data.remove(preview);
					removed = true;
				}
			}
			if (removed) {
				fireTableDataChanged();
			}
			return removed;
		}

		private boolean isValid(DataType dt) {
			if (dt == null) {
				return false;
			}

			if (dt instanceof DynamicDataType) {
				tool.setStatusInfo("Dynamic data types do not support previewing.");
				return false;
			}
			if (dt instanceof FactoryStructureDataType) {
				tool.setStatusInfo("Dynamic structure data types do not support previewing.");
				return false;
			}
			if (dt instanceof FunctionDefinition || dt instanceof FunctionDefinitionDataType) {
				tool.setStatusInfo("Function definition data types do not support previewing.");
				return false;
			}
			return true;
		}

		private boolean contains(DataType dt) {
			Iterator<Preview> iter = data.iterator();
			while (iter.hasNext()) {
				Preview p = iter.next();
				if (p.getDataType().equals(dt) || p.getDataType().isEquivalent(dt)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public String getName() {
			return "Datatype Preview";
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			return false;
		}

		@Override
		public String getColumnName(int col) {
			if (col == NAME_COL) {
				return "Name";
			}
			else if (col == PREVIEW_COL) {
				return "Preview";
			}
			return "<<unknown>>";
		}

		@Override
		public int getRowCount() {
			if (data == null) {
				return 0;
			}
			return data.size();
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public Object getColumnValueForRow(Preview p, int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return p.getName();
				case PREVIEW_COL:
					if (currentProgram != null && currentAddress != null) {
						return p.getPreview(currentProgram.getMemory(), currentAddress);
					}
				default:
					return null;
			}
		}

		@Override
		public List<Preview> getModelData() {
			return data;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		protected Comparator<Preview> createSortComparator(int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return new NamePreviewColumnComparator();
				case PREVIEW_COL:
					return new PreviewColumnComparator();
				default:
					return super.createSortComparator(columnIndex);
			}
		}

		private class NamePreviewColumnComparator implements Comparator<Preview> {
			@Override
			public int compare(Preview p1, Preview p2) {
				if (currentProgram == null || currentAddress == null) {
					return 0;
				}

				return p1.compareTo(p2);
			}
		}

		private class PreviewColumnComparator implements Comparator<Preview> {
			@Override
			public int compare(Preview p1, Preview p2) {
				if (currentProgram == null || currentAddress == null) {
					return 0;
				}

				String preview1 = p1.getPreview(currentProgram.getMemory(), currentAddress);
				String preview2 = p2.getPreview(currentProgram.getMemory(), currentAddress);
				return preview1.compareToIgnoreCase(preview2);
			}
		}
	}

	private DataTypeManager createLayeredDataTypeManager() {
		DataOrganization dataOrg =
			(activeProgram != null) ? activeProgram.getCompilerSpec().getDataOrganization()
					: DataOrganizationImpl.getDefaultOrganization();
		return new StandAloneDataTypeManager(ROOT_NAME, dataOrg);
	}

}
