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
package ghidra.app.plugin.core.references;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.action.*;
import docking.dnd.DropTgtAdapter;
import docking.dnd.Droppable;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.table.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.util.SelectionTransferData;
import ghidra.app.util.SelectionTransferable;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

public class EditReferencesProvider extends ComponentProviderAdapter
		implements DomainObjectListener, ChangeListener {

	private static final String ADD_REFS_GROUP = "AddReferences";

	private static final HelpLocation HELP =
		new HelpLocation("ReferencesPlugin", "View_Edit_References_From");

	private static Icon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private static Icon EDIT_ICON = ResourceManager.loadImage("images/editbytes.gif");
	private static Icon DELETE_ICON = ResourceManager.loadImage("images/edit-delete.png");
	private static Icon RECV_LOCATION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;
	//private static Icon RECV_LOCATION_OFF_ICON = ResourceManager.loadImage("images/locationInOff.gif");
	private static Icon SEND_LOCATION_ICON = Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON;
	//private static Icon SEND_LOCATION_OFF_ICON = ResourceManager.loadImage("images/locationOutOff.gif");
	private static Icon HOME_ICON = ResourceManager.loadImage("images/go-home.png");
	private static Icon SELECT_ICON = ResourceManager.loadImage("images/text_align_justify.png");

	private static final String TITLE_PREFIX = "References Editor ";

	static int MNEMONIC_OPINDEX = ReferenceManager.MNEMONIC;

	static Color HIGHLIGHT_COLOR = new Color(205, 205, 205);

	private static final DataFlavor[] ACCEPTABLE_DROP_FLAVORS =
		new DataFlavor[] { SelectionTransferable.localProgramSelectionFlavor };

	private ReferencesPlugin plugin;

	private SwingUpdateManager updateMgr;

	private CodeUnit currentCodeUnit;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	private JPanel panel;
	private InstructionPanel instrPanel;
	private GhidraTable refsTable;
	private DropTarget tableDropTarget;
	private DropTarget scrollPaneDropTarget;
	private EditReferencesModel tableModel;
	private boolean selectionBusy;

	private DockingAction addRefAction;
	private DockingAction editRefAction;
	private DockingAction deleteRefAction;
	private ToggleDockingAction followLocationToggleAction;
	private ToggleDockingAction gotoReferenceLocationToggleAction;
	private DockingAction goHomeAction;
	private DockingAction selectAction;

	private ProgramLocation initLocation;

	private DropTgtAdapter dropTargetAdapter;
	private Droppable dropHandler = new Droppable() {

		/**
		 * Set drag feedback according to the ok parameter.
		 * 
		 * @param ok true means the drop action is OK
		 * @param e event that has current state of drag and drop operation
		 */
		@Override
		public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
			// don't care
		}

		/**
		 * Return true if is OK to drop the transferable at the location
		 * specified the event.
		 * 
		 * @param e event that has current state of drag and drop operation
		 */
		@Override
		public boolean isDropOk(DropTargetDragEvent e) {
			if (currentCodeUnit != null) {
				Memory memory = currentCodeUnit.getProgram().getMemory();
				try {
					Object data = e.getTransferable().getTransferData(
						SelectionTransferable.localProgramSelectionFlavor);
					AddressSetView view = ((SelectionTransferData) data).getAddressSet();
					if (memory.contains(view)) {
						return true;
					}
				}
				catch (UnsupportedFlavorException e1) {
					// handle below by returning false
				}
				catch (IOException e1) {
					// handle below by returning false
				}
			}
			return false;
		}

		/**
		 * Revert back to normal if any drag feedback was set.
		 */
		@Override
		public void undoDragUnderFeedback() {
			// don't care
		}

		/**
		 * Add the object to the droppable component. The DropTargetAdapter
		 * calls this method from its drop() method.
		 * 
		 * @param obj Transferable object that is to be dropped; in this case,
		 *            it is an AddressSetView
		 * @param e has current state of drop operation
		 * @param f represents the opaque concept of a data format as would
		 *            appear on a clipboard, during drag and drop.
		 */
		@Override
		public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
			AddressSetView view = ((SelectionTransferData) obj).getAddressSet();
			if (view.getNumAddressRanges() == 0) {
				return;
			}
			plugin.addMemoryReferences(panel, view, currentCodeUnit,
				instrPanel.getSelectedOpIndex(), true);
		}

	};

	EditReferencesProvider(ReferencesPlugin plugin) {
		super(plugin.getTool(), TITLE_PREFIX, plugin.getName());
		this.plugin = plugin;
		tableModel = new EditReferencesModel(plugin);
		setHelpLocation(HELP);
		updateMgr = new SwingUpdateManager(100, 2000, () -> doUpdate());

		setTransient();
		setWindowMenuGroup(TITLE_PREFIX);

		tool.addComponentProvider(this, false);
	}

	private void setupActions() {

		addRefAction = new DockingAction("Add Reference", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addCallback();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		addRefAction.setDescription("Add forward reference");
		addRefAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_INSERT, 0)));
		addRefAction.setPopupMenuData(
			new MenuData(new String[] { "Add..." }, ADD_ICON, ADD_REFS_GROUP));
		addRefAction.setToolBarData(new ToolBarData(ADD_ICON, "EditAction"));
		addRefAction.setEnabled(true);
		tool.addLocalAction(this, addRefAction);

		deleteRefAction = new DockingAction("Delete References", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				deleteCallback();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		deleteRefAction.setDescription("Delete references");
		deleteRefAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0)));
		deleteRefAction.setPopupMenuData(
			new MenuData(new String[] { "Delete..." }, DELETE_ICON, ADD_REFS_GROUP));
		deleteRefAction.setToolBarData(new ToolBarData(DELETE_ICON, "EditAction"));
		deleteRefAction.setEnabled(false);
		tool.addLocalAction(this, deleteRefAction);

		editRefAction = new DockingAction("Edit Reference", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				editCallback();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		editRefAction.setDescription("Edit reference");
		editRefAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0)));
		editRefAction.setPopupMenuData(
			new MenuData(new String[] { "Edit..." }, EDIT_ICON, ADD_REFS_GROUP));
		editRefAction.setToolBarData(new ToolBarData(EDIT_ICON, "EditAction"));
		editRefAction.setEnabled(false);
		tool.addLocalAction(this, editRefAction);

		selectAction = new DockingAction("Select Destinations", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (currentProgram != null) {
					selectReferenceLocations();
				}
			}
		};
		selectAction.setDescription("Select reference destinations");
		selectAction.setToolBarData(new ToolBarData(SELECT_ICON, "NavAction"));
		selectAction.setEnabled(true);
		tool.addLocalAction(this, selectAction);

		followLocationToggleAction =
			new ToggleDockingAction("Follow location changes", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					enableFollowLocation(followLocationToggleAction.isSelected());
				}
			};
		followLocationToggleAction.setEnabled(true);
		followLocationToggleAction.setToolBarData(new ToolBarData(RECV_LOCATION_ICON, "NavAction"));
		tool.addLocalAction(this, followLocationToggleAction);

		gotoReferenceLocationToggleAction =
			new ToggleDockingAction("GoTo selected destination", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					enableGotoReferenceLocation(gotoReferenceLocationToggleAction.isSelected());
				}
			};
		gotoReferenceLocationToggleAction.setToolBarData(
			new ToolBarData(SEND_LOCATION_ICON, "NavAction"));
		gotoReferenceLocationToggleAction.setEnabled(true);
		tool.addLocalAction(this, gotoReferenceLocationToggleAction);

		goHomeAction = new DockingAction("GoTo source location", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (currentProgram != null) {
					plugin.goTo(currentProgram, currentLocation);
				}
			}

		};
		goHomeAction.setToolBarData(new ToolBarData(HOME_ICON, "NavAction"));
		goHomeAction.setDescription("GoTo reference source location");
		goHomeAction.setEnabled(true);
		tool.addLocalAction(this, goHomeAction);
		enableGotoReferenceLocation(plugin.getDefaultGotoReferenceLocation());
		enableFollowLocation(plugin.getDefaultFollowOnLocation());

	}

	private String generateTitle() {
		String suffix = currentCodeUnit != null
				? "@ " + currentCodeUnit.getMinAddress() + "  (" +
					currentProgram.getDomainFile().getName() + ")"
				: "";
		return TITLE_PREFIX + suffix;
	}

	private void selectReferenceLocations() {
		AddressSet set = new AddressSet();
		int[] selRows = refsTable.getSelectedRows();
		for (int selRow : selRows) {
			Reference ref = tableModel.getReference(selRow);
			Address addr = ref.getToAddress();
			if (addr.isMemoryAddress()) {
				set.addRange(addr, addr);
			}
		}
		ProgramSelection sel = new ProgramSelection(set);
		plugin.firePluginEvent(
			new ProgramSelectionPluginEvent(plugin.getName(), sel, currentProgram));
	}

	private synchronized void doUpdate() {
		if (currentProgram == null) {
			return;
		}

		CodeUnit cu = getCurrentCodeUnit(currentProgram);
		if (cu == null) {
			show(null, null);
		}
		else {

			selectionBusy = true;
			try {
				int[] selRows = refsTable.getSelectedRows();
				ArrayList<Reference> selRefList = new ArrayList<>();
				for (int row : selRows) {
					selRefList.add(tableModel.getReference(row));
				}

				int opIndex = instrPanel.getSelectedOpIndex();
				int subIndex = instrPanel.getSelectedSubOpIndex();
				currentCodeUnit = cu;
				int opCnt = cu.getNumOperands();
				if (opIndex >= opCnt) {
					opIndex = opCnt > 0 ? 0 : MNEMONIC_OPINDEX;
					subIndex = -1;
				}

				init(opIndex, subIndex);

				if (!selRefList.isEmpty()) {
					ListSelectionModel selModel = refsTable.getSelectionModel();
					for (Reference ref : selRefList) {
						int row = tableModel.getRow(ref);
						if (row != -1) {
							selModel.addSelectionInterval(row, row);
						}
					}
				}
			}
			finally {
				selectionBusy = false;
			}
		}
	}

	public synchronized void dispose() {
		updateMgr.dispose();
		if (plugin != null) {
			tool.removeComponentProvider(this);
			plugin = null;
		}

		clearProgramState();

		if (tableModel != null) {
			tableModel.setCodeUnitLocation(null);
			tableModel = null;
		}

		refsTable.dispose();

		if (instrPanel != null) {
			instrPanel.setCodeUnitLocation(null, MNEMONIC_OPINDEX, -1, false);
		}
		tool = null;
	}

	synchronized void updateForLocation(Program program, ProgramLocation loc) {
		ReferenceInfo referenceInfo = initializeFromLocation(program, loc);
		init(referenceInfo);
	}

	synchronized void show(Program p, ProgramLocation loc) {
		ReferenceInfo referenceInfo = initializeFromLocation(p, loc);

		if (!tool.isVisible(this)) {
			tool.showComponentProvider(this, true);
			setupActions();
		}
		else {
			init(referenceInfo);
			tool.toFront(this);
		}
	}

	private ReferenceInfo initializeFromLocation(Program p, ProgramLocation loc) {
		currentLocation = loc;
		initLocation = loc;

		clearProgramState();

		if (p == null) {
			return null;
		}

		ReferenceInfo referenceInfo = getReferenceInfo(p, loc);
		this.currentCodeUnit = referenceInfo.codeUnit;
		this.currentProgram = referenceInfo.program;

		if (currentProgram != null) {
			currentProgram.addListener(this);
		}

		return referenceInfo;
	}

	private ReferenceInfo getReferenceInfo(Program p, ProgramLocation loc) {
		ReferenceInfo info = new ReferenceInfo();
		if (loc == null) {
			return info;
		}

		info.program = p;
		info.codeUnit = getCurrentCodeUnit(p);
		if (loc instanceof OperandFieldLocation) {
			OperandFieldLocation operandFieldLocation = (OperandFieldLocation) loc;
			info.opIndex = operandFieldLocation.getOperandIndex();
			info.subIndex = operandFieldLocation.getSubOperandIndex();
		}
		else {
			info.opIndex = MNEMONIC_OPINDEX;
		}

		if (info.codeUnit == null) {
			info.program = null;
		}
		else if (info.codeUnit instanceof Instruction) {
			Instruction instruction = (Instruction) info.codeUnit;
			if (instruction.getNumOperands() == 0) {
				info.opIndex = MNEMONIC_OPINDEX;
			}
		}

		return info;
	}

	private void clearProgramState() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
			currentCodeUnit = null;
		}
	}

	Program getCurrentProgram() {
		return currentProgram;
	}

	public CodeUnit getCodeUnit() {
		return getCurrentCodeUnit(currentProgram);
	}

	public CodeUnit getCodeUnit(Program currProgram, ProgramLocation currLocation) {
		CodeUnit cu = null;
		if ((currProgram != null) && (currLocation != null)) {
			Address addr = currLocation.getAddress();
			Listing listing = currProgram.getListing();
			Data data = DataUtilities.getDataAtLocation(currLocation);
			if (data == null) {
				cu = listing.getCodeUnitAt(addr);
			}
			else {
				Data d = listing.getDataContaining(addr);
				cu = findComponent(d, addr);
			}
		}
		return cu;
	}

	public ProgramLocation getInitLocation() {
		return initLocation;
	}

	private CodeUnit getCurrentCodeUnit(Program theProgram) {
		if (currentLocation == null) {
			return null;
		}

		Address addr = currentLocation.getAddress();
		Listing listing = theProgram.getListing();
		Data data = DataUtilities.getDataAtLocation(currentLocation);
		if (data == null) {
			return listing.getCodeUnitAt(addr);
		}

		Data d = listing.getDataContaining(addr);
		return findComponent(d, addr);
	}

	/**
	 * Find the Data at the currentCuAddress
	 * 
	 * @param data place to begin searching
	 * @return Data starting at currentCuAddress
	 */
	private Data findComponent(Data data, Address addr) {
		while (addr.compareTo(data.getMinAddress()) >= 0) {
			long offset = addr.subtract(data.getMinAddress());
			Data d = data.getComponentAt((int) offset);
			if (d == null) {
				break;
			}
			data = d;
		}
		return data;
	}

	private void init(ReferenceInfo info) {
		int opIndex = Reference.MNEMONIC;
		int subIndex = 0;
		if (info != null) {
			opIndex = info.opIndex;
			subIndex = info.subIndex;
		}
		init(opIndex, subIndex);
	}

	private void init(int opIndex, int subIndex) {
		setTitle(generateTitle());
		refsTable.clearSelection();
		tableModel.setCodeUnitLocation(currentCodeUnit);
		instrPanel.setCodeUnitLocation(currentCodeUnit, opIndex, subIndex, false);
		adjustActionState();
		tableDropTarget.setActive(currentCodeUnit != null);
		scrollPaneDropTarget.setActive(currentCodeUnit != null);
	}

	@Override
	public void closeComponent() {

		// end any table editing; this prevents exceptions on focus changes when closing this editor
		refsTable.editingStopped(new ChangeEvent(refsTable));
		super.closeComponent();
		plugin.providerClosed(this);
	}

	@Override
	public void componentHidden() {
		plugin.getCodeUnitFormat().removeChangeListener(this);
	}

	@Override
	public void componentShown() {
		plugin.getCodeUnitFormat().addChangeListener(this);
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		if (panel != null && panel.isVisible()) {
			panel.repaint();
		}
	}

	@Override
	public JComponent getComponent() {
		if (panel != null) {
			return panel;
		}
		panel = new JPanel(new BorderLayout());
		panel.setPreferredSize(new Dimension(600, 200));

		instrPanel =
			new InstructionPanel(0, 5, 0, 5, goHomeAction, plugin, new InstructionPanelListener() {
				@Override
				public boolean dropSupported() {
					return true;
				}

				@Override
				public void operandSelected(int opIndex, int subIndex) {
					if (!selectionBusy) {
						selectionBusy = true;
						refsTable.getSelectionModel().clearSelection();
						updateLocation();
						adjustActionState();
						selectionBusy = false;
					}
					getComponent().repaint();
				}

				@Override
				public void selectionDropped(AddressSetView set, CodeUnit cu, int opIndex) {
					plugin.addMemoryReferences(panel, set, cu, opIndex, false);
				}
			});

		panel.add(instrPanel, BorderLayout.NORTH);

		refsTable = new GhidraTable(tableModel);
		refsTable.setName("RefsTable");
		//table.getInputMap().remove(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0));
		JScrollPane sp = new JScrollPane(refsTable);
		refsTable.setPreferredScrollableViewportSize(new Dimension(200, 400));
		refsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		refsTable.getSelectionModel().addListSelectionListener(e -> {
			if (!selectionBusy && !e.getValueIsAdjusting()) {
				selectionBusy = true;
				int[] selRows = refsTable.getSelectedRows();
				if (selRows.length == 1) {
					// Only one ref selected
					int opIndex = tableModel.getReference(selRows[0]).getOperandIndex();
					instrPanel.setSelectedOpIndex(opIndex, -1);
					followSelectedReference();
				}
//					else {
//						int opIndex = MNEONIC_OPINDEX;
//						if (selRows.length != 0) {
//							opIndex = tableModel.getReference(selRows[0]).getOperandIndex();
//						}
//						instrPanel.setSelectedOpIndex(opIndex);
//					}
				selectionBusy = false;
				updateLocation();
				adjustActionState();
			}
		});
		refsTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (refsTable.rowAtPoint(e.getPoint()) != -1) {
					if (e.getClickCount() == 1) {
						followSelectedReference();
					}
					else if (e.getClickCount() == 2) {
						editCallback();
					}
				}
			}
		});

		TableColumn col = refsTable.getColumnModel().getColumn(EditReferencesModel.IS_PRIMARY_COL);
		col.setMinWidth(75);
		col.setMaxWidth(75);
		col.setResizable(false);
		col = refsTable.getColumnModel().getColumn(EditReferencesModel.REF_SOURCE_COL);
		col.setMinWidth(80);
		col.setMaxWidth(80);
		col.setResizable(false);

		ToolTipManager.sharedInstance().registerComponent(refsTable);

		dropTargetAdapter = new DropTgtAdapter(dropHandler, DnDConstants.ACTION_COPY_OR_MOVE,
			ACCEPTABLE_DROP_FLAVORS);
		tableDropTarget =
			new DropTarget(refsTable, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		scrollPaneDropTarget =
			new DropTarget(sp, DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
		tableDropTarget.setActive(false);
		scrollPaneDropTarget.setActive(false);

		//JTableHeader header = table.getTableHeader();
		TableColumnModel columnModel = refsTable.getColumnModel();
		RefCellTextRenderer textCellRenderer = new RefCellTextRenderer();
		RefCellBooleanRenderer booleanCellRenderer = new RefCellBooleanRenderer();
		RefCellBooleanEditor booleanCellEditor = new RefCellBooleanEditor();

		// Establish cell renderers
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			if (i == EditReferencesModel.IS_PRIMARY_COL) {
				column.setCellRenderer(booleanCellRenderer);
				column.setCellEditor(booleanCellEditor);
			}
			else if (i == EditReferencesModel.REF_TYPE_COL) {
				column.setCellRenderer(textCellRenderer);
				column.setCellEditor(new RefTypeCellEditor());
			}
			else {
				column.setCellRenderer(textCellRenderer);
			}
		}

		adjustTableColumns();

		panel.add(sp, BorderLayout.CENTER);

		int opIndex = MNEMONIC_OPINDEX;
		int subIndex = -1;
		if (currentLocation instanceof OperandFieldLocation) {
			opIndex = ((OperandFieldLocation) currentLocation).getOperandIndex();
			subIndex = ((OperandFieldLocation) currentLocation).getSubOperandIndex();
		}
		init(opIndex, subIndex);

		return panel;
	}

	/**
	 * Size the columns such that the interesting ones are wider than the
	 * uninteresting columns.
	 */
	private void adjustTableColumns() {
		refsTable.sizeColumnsToFit(-1);
		TableColumn column = refsTable.getColumn(EditReferencesModel.OPERAND);
		column.setPreferredWidth(80);
		column = refsTable.getColumn(EditReferencesModel.LOCATION);
		column.setPreferredWidth(100);
		column = refsTable.getColumn(EditReferencesModel.LABEL);
		column.setPreferredWidth(150);
		column = refsTable.getColumn(EditReferencesModel.REF_TYPE);
		column.setPreferredWidth(150);
		column = refsTable.getColumn(EditReferencesModel.IS_PRIMARY);
		column.setPreferredWidth(60);
		column = refsTable.getColumn(EditReferencesModel.REF_SOURCE);
		column.setPreferredWidth(70);
	}

	private void updateLocation() {
		if (currentLocation != null) {
			int opIndex = instrPanel.getSelectedOpIndex();
			if (opIndex == MNEMONIC_OPINDEX) {
				currentLocation = new MnemonicFieldLocation(currentLocation.getProgram(),
					currentLocation.getAddress(), currentLocation.getComponentPath(), "", 0);
			}
			else {
				currentLocation = new OperandFieldLocation(currentLocation.getProgram(),
					currentLocation.getAddress(), currentLocation.getComponentPath(), null, "",
					opIndex, 0);
			}
		}
	}

	private void adjustActionState() {
		boolean validCodeUnit = (currentProgram != null && currentCodeUnit != null);
		int selRowCnt = refsTable.getSelectedRowCount();
		addRefAction.setEnabled(validCodeUnit);
		deleteRefAction.setEnabled(selRowCnt != 0 || refsTable.getSelectedRowCount() != 0);
		editRefAction.setEnabled(selRowCnt == 1);
		goHomeAction.setEnabled(validCodeUnit);
	}

	boolean isLocationLocked() {
		return followLocationToggleAction != null && !followLocationToggleAction.isSelected();
	}

	void enableFollowLocation(boolean state) {
		if (state) {
			enableGotoReferenceLocation(false);
		}
		followLocationToggleAction.setSelected(state);
		String descr = "Enable/Disable following tool location changes";
		followLocationToggleAction.setDescription(HTMLUtilities.toHTML(descr));
		plugin.setDefaultFollowOnLocation(state);
	}

	void enableGotoReferenceLocation(boolean state) {
		if (state) {
			enableFollowLocation(false);
		}
		gotoReferenceLocationToggleAction.setSelected(state);
		String descr = "Enable/Disable sending location change for selected row";
		gotoReferenceLocationToggleAction.setDescription(HTMLUtilities.toHTML(descr));
		if (state) {
			followSelectedReference();
		}
		plugin.setDefaultGotoReferenceLocation(state);
	}

	private void followSelectedReference() {
		if (refsTable == null) {
			return;
		}
		if (gotoReferenceLocationToggleAction.isSelected() &&
			refsTable.getSelectedRowCount() == 1) {
			Reference ref = tableModel.getReference(refsTable.getSelectedRow());
			Variable var = currentProgram.getReferenceManager().getReferencedVariable(ref);
			if (var != null) {
				plugin.goTo(currentProgram, new VariableNameFieldLocation(currentProgram, var, 0));
			}
			else if (ref.getToAddress().isMemoryAddress()) {
				plugin.goTo(currentProgram, ref.getToAddress());
			}
		}
	}

	private void addCallback() {
		if (currentCodeUnit != null) {
			plugin.popupAddReferenceDialog(currentCodeUnit, instrPanel.getSelectedOpIndex(),
				instrPanel.getSelectedSubOpIndex(), this);
		}
	}

	private void editCallback() {
		if (currentCodeUnit != null && refsTable.getSelectedRowCount() == 1) {
			Reference ref = tableModel.getReference(refsTable.getSelectedRow());
			if (ref != null) {
				plugin.popupEditReferenceDialog(currentCodeUnit, ref, this);
			}
		}
	}

	private void deleteCallback() {
		// cancel any pending edits before deleting, as not to trigger explosions
		refsTable.editingCanceled(new ChangeEvent(refsTable));

		int[] selRows = refsTable.getSelectedRows();
		if (selRows.length != 0) {
			Reference[] refs = new Reference[selRows.length];
			for (int i = 0; i < selRows.length; i++) {
				refs[i] = tableModel.getReference(selRows[i]);
			}
			plugin.deleteReferences(currentProgram, refs);
		}
	}

	@Override
	public synchronized void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (currentProgram == null) {
			return;
		}
		updateMgr.updateLater();

	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/** Fun little storage object */
	private class ReferenceInfo {
		private Program program;
		private CodeUnit codeUnit;
		private int opIndex = 0;
		private int subIndex = -1;
	}

	private class RefTypeCellEditor extends DefaultCellEditor {

		private CellEditComboBox comboBox;

		RefTypeCellEditor() {
			super(new CellEditComboBox());
			comboBox = (CellEditComboBox) editorComponent;
			comboBox.setFont(refsTable.getFont());

			// This triggers the edit to stop when the user clicks away from the editor
			comboBox.addFocusListener(new FocusAdapter() {
				@Override
				public void focusLost(FocusEvent e) {
					stopCellEditing();
				}
			});
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {

			column = table.convertColumnIndexToModel(column);
			if (column != EditReferencesModel.REF_TYPE_COL) {
				throw new RuntimeException("Incorrect column for RefTypeCellRenderer");
			}

			Reference ref = tableModel.getReference(row);
			RefType[] refTypes = EditReferencesModel.getAllowedRefTypes(
				EditReferencesProvider.this.currentProgram, ref);

			comboBox.removeAllItems();
			int selectedIndex = -1;
			for (RefType rt : refTypes) {
				if (rt == value) {
					selectedIndex = comboBox.getItemCount();
				}
				comboBox.addItem(rt);
			}
			if (selectedIndex < 0) {
				comboBox.insertItemAt((RefType) value, 0);
				selectedIndex = 0;
			}
			comboBox.setSelectedIndex(selectedIndex);

			return comboBox;
		}
	}

	private class CellEditComboBox extends JComboBox<RefType> {

		public CellEditComboBox() {
			super();
		}

		@Override
		public void setSelectedIndex(int anIndex) {
			if (refsTable.getRowCount() == 0) {
				refsTable.editingCanceled(null);
				return;
			}

			super.setSelectedIndex(anIndex);
		}

	}

	private class RefCellBooleanRenderer extends GBooleanCellRenderer {

		RefCellBooleanRenderer() {
			// cb.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnModelIndex();
			boolean isSelected = data.isSelected();

			Reference ref = tableModel.getReference(row);

			// Only the IS_PRIMARY_COLUMN is editable in certain cases
			boolean enabled = false;
			if (column == EditReferencesModel.IS_PRIMARY_COL) {
				enabled = tableModel.isCellEditable(row, column);
			}
			cb.setEnabled(enabled);
			cb.setOpaque(false);
			cb.setFont(table.getFont());

			if (!isSelected) {
				if (ref.getOperandIndex() == instrPanel.getSelectedOpIndex()) {
					cb.setBackground(HIGHLIGHT_COLOR);
					setBackground(HIGHLIGHT_COLOR);
					cb.setOpaque(true);
				}
			}

			return this;
		}

		@Override
		public boolean shouldAlternateRowBackgroundColor() {
			return false; // this table uses colors to signal row information--skip alternating
		}
	}

	private class RefCellBooleanEditor extends DefaultCellEditor {

		private JCheckBox checkbox;

		RefCellBooleanEditor() {
			super(new GCheckBox());
			setClickCountToStart(1);
			checkbox = (JCheckBox) editorComponent;
			checkbox.setOpaque(false);
			checkbox.setHorizontalAlignment(SwingConstants.CENTER);
			checkbox.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {

			column = table.convertColumnIndexToModel(column);

			Reference ref = tableModel.getReference(row);

			checkbox.setSelected(((Boolean) value).booleanValue());

			// Only the IS_PRIMARY_COLUMN is editable
			checkbox.setEnabled(column == EditReferencesModel.IS_PRIMARY_COL);

			checkbox.setFont(table.getFont());
			if (isSelected) {
				checkbox.setForeground(table.getSelectionForeground());
				checkbox.setBackground(table.getSelectionBackground());
				checkbox.setOpaque(true);
			}
			else {
				if (ref.getOperandIndex() == instrPanel.getSelectedOpIndex()) {
					checkbox.setForeground(table.getForeground());
					checkbox.setBackground(HIGHLIGHT_COLOR);
					checkbox.setOpaque(true);
				}
				else {
					checkbox.setForeground(table.getForeground());
					checkbox.setBackground(table.getBackground());
					checkbox.setOpaque(false);
				}
			}

			return checkbox;
		}
	}

	private class RefCellTextRenderer extends GTableCellRenderer {

		RefCellTextRenderer() {
			defaultFont = getFont();
			boldFont = new Font(defaultFont.getName(), defaultFont.getStyle() | Font.BOLD,
				defaultFont.getSize());
			setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			boolean isSelected = data.isSelected();

			Reference ref = tableModel.getReference(row);

			Address addr = ref.getToAddress();
			Memory memory = tableModel.getProgram().getMemory();
			boolean bad = addr.isMemoryAddress() ? !memory.contains(addr) : false;

			setOpaque(false); // disable table striping
			setFont(table.getFont());

			if (isSelected) {
				if (bad) {
					setForeground(Color.pink);
					setFont(boldFont);
				}
				else {
					setFont(defaultFont);
				}

				setOpaque(true);
			}
			else {
				// set color to red if address does not exist in memory

				if (bad) {
					setForeground(Color.red);
					setFont(boldFont);
				}
				else {
					setFont(defaultFont);
				}
				if (ref.getOperandIndex() == instrPanel.getSelectedOpIndex()) {
					setBackground(HIGHLIGHT_COLOR);
					setOpaque(true);
				}
			}

			return this;
		}
	}
}
