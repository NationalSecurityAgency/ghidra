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
package ghidra.app.plugin.core.symtable;

import java.awt.Cursor;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.symboltree.actions.*;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.GoToService;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

/**
 * Plugin to display the symbol table for a program.
 * Allows navigation and changing the symbol name.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Show Symbols in Symbol Table",
	description = "This plugin shows the symbols in the symbol table," +
			" provides navigation to the symbols in the Code Browser, and " +
			"allows symbols to be renamed and deleted. This plugin also " +
			"shows references to a symbol. Filters can be set " +
			"to show subsets of the symbols.",
	servicesRequired = { GoToService.class, BlockModelService.class },
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class SymbolTablePlugin extends Plugin implements DomainObjectListener {

	final static Cursor WAIT_CURSOR = new Cursor(Cursor.WAIT_CURSOR);
	final static Cursor NORM_CURSOR = new Cursor(Cursor.DEFAULT_CURSOR);

	private DockingAction openRefsAction;
	private DockingAction deleteAction;
	private DockingAction makeSelectionAction;
	private DockingAction setFilterAction;
	private ToggleDockingAction referencesToAction;
	private ToggleDockingAction instructionsFromAction;
	private ToggleDockingAction dataFromAction;

	private SymbolProvider symProvider;
	private ReferenceProvider refProvider;
	private SymbolInspector inspector;
	private Program currentProgram;
	private GoToService gotoService;
	private BlockModelService blockModelService;
	private SwingUpdateManager swingMgr;

	public SymbolTablePlugin(PluginTool tool) {
		super(tool);

		swingMgr = new SwingUpdateManager(1000, () -> {
			symProvider.getComponent().repaint();
			refProvider.getComponent().repaint();
		});
	}

	@Override
	protected void init() {
		gotoService = tool.getService(GoToService.class);
		blockModelService = tool.getService(BlockModelService.class);

		symProvider = new SymbolProvider(this);
		refProvider = new ReferenceProvider(this);

		createSymActions();
		createRefActions();

		inspector = new SymbolInspector(getTool(), symProvider.getComponent());
	}

	/**
	 * Tells a plugin that it is no longer needed.
	 * The plugin should remove itself from anything that
	 * it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		super.dispose();
		swingMgr.dispose();

		deleteAction.dispose();
		makeSelectionAction.dispose();

		if (symProvider != null) {
			symProvider.dispose();
			symProvider = null;
		}
		if (refProvider != null) {
			refProvider.dispose();
			refProvider = null;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}
		gotoService = null;
		blockModelService = null;

		if (inspector != null) {
			inspector.dispose();
			inspector = null;
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		symProvider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		symProvider.writeConfigState(saveState);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent progEvent = (ProgramActivatedPluginEvent) event;
			Program oldProg = currentProgram;
			Program newProg = progEvent.getActiveProgram();

			if (oldProg != null) {
				inspector.setProgram(null);
				oldProg.removeListener(this);
				symProvider.setProgram(null, inspector);
				refProvider.setProgram(null, inspector);
				tool.contextChanged(symProvider);
			}
			currentProgram = newProg;
			if (newProg != null) {

				currentProgram.addListener(this);

				inspector.setProgram(currentProgram);

				symProvider.setProgram(currentProgram, inspector);
				refProvider.setProgram(currentProgram, inspector);
			}

			tool.contextChanged(symProvider);
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!symProvider.isVisible()) {
			return;
		}
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED)) {

			symProvider.reload();
			refProvider.reload();
			return;
		}

		int eventCnt = ev.numRecords();
		for (int i = 0; i < eventCnt; ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);

			int eventType = doRecord.getEventType();
			if (!(doRecord instanceof ProgramChangeRecord)) {
				continue;
			}

			ProgramChangeRecord rec = (ProgramChangeRecord) doRecord;
			Symbol symbol = null;
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			switch (eventType) {
				case ChangeManager.DOCR_CODE_ADDED:
				case ChangeManager.DOCR_CODE_REMOVED:
					if (rec.getNewValue() instanceof Data) {
						symbol = symbolTable.getPrimarySymbol(rec.getStart());
						if (symbol != null && symbol.isDynamic()) {
							symProvider.symbolChanged(symbol);
							refProvider.symbolChanged(symbol);
						}
					}
					break;

				case ChangeManager.DOCR_SYMBOL_ADDED:
					Address addAddr = rec.getStart();
					Symbol primaryAtAdd = symbolTable.getPrimarySymbol(addAddr);
					if (primaryAtAdd != null && primaryAtAdd.isDynamic()) {
						symProvider.symbolRemoved(primaryAtAdd);
					}
					symbol = (Symbol) rec.getNewValue();
					symProvider.symbolAdded(symbol);
					refProvider.symbolAdded(symbol);
					break;

				case ChangeManager.DOCR_SYMBOL_REMOVED:
					Address removeAddr = rec.getStart();
					Long symbolID = (Long) rec.getNewValue();
					Symbol removedSymbol =
						symbolTable.createSymbolPlaceholder(removeAddr, symbolID);
					symProvider.symbolRemoved(removedSymbol);
					refProvider.symbolRemoved(removedSymbol);
					Symbol primaryAtRemove = symbolTable.getPrimarySymbol(removeAddr);
					if (primaryAtRemove != null && primaryAtRemove.isDynamic()) {
						symProvider.symbolAdded(primaryAtRemove);
					}
					break;

				case ChangeManager.DOCR_SYMBOL_RENAMED:
				case ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED:
				case ChangeManager.DOCR_SYMBOL_DATA_CHANGED:
					symbol = (Symbol) rec.getObject();
					if (!symbol.isDeleted()) { // symbol may have been removed (e.g., parameter)
						symProvider.symbolChanged(symbol);
						refProvider.symbolChanged(symbol);
					}
					break;

				case ChangeManager.DOCR_SYMBOL_SOURCE_CHANGED:
					symbol = (Symbol) rec.getObject();
					symProvider.symbolChanged(symbol);
					break;

				case ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY:
					symbol = (Symbol) rec.getNewValue();
					symProvider.symbolChanged(symbol);
					Symbol oldSymbol = (Symbol) rec.getOldValue();
					if (oldSymbol != null) {
						symProvider.symbolChanged(oldSymbol);
					}
					break;

				case ChangeManager.DOCR_SYMBOL_ASSOCIATION_ADDED:
				case ChangeManager.DOCR_SYMBOL_ASSOCIATION_REMOVED:
					break;
				case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
					Reference ref = (Reference) rec.getObject();
					symbol = symbolTable.getSymbol(ref);
					if (symbol != null) {
						symProvider.symbolChanged(symbol);
						refProvider.symbolChanged(symbol);
					}
					break;
				case ChangeManager.DOCR_MEM_REFERENCE_REMOVED:
					ref = (Reference) rec.getObject();
					Address toAddr = ref.getToAddress();
					if (toAddr.isMemoryAddress()) {
						symbol = symbolTable.getSymbol(ref);
						if (symbol == null) {

							long id = symbolTable.getDynamicSymbolID(ref.getToAddress());
							removedSymbol = symbolTable.createSymbolPlaceholder(toAddr, id);
							symProvider.symbolRemoved(removedSymbol);
						}
						else {
							refProvider.symbolChanged(symbol);
						}
					}
					break;

				case ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_ADDED:
				case ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_REMOVED:
					Symbol[] symbols = symbolTable.getSymbols(rec.getStart());
					for (Symbol element : symbols) {
						symProvider.symbolChanged(element);
						refProvider.symbolChanged(element);
					}
					break;
			}
		}
	}

	Program getProgram() {
		return currentProgram;
	}

	BlockModelService getBlockModelService() {
		return blockModelService;
	}

	GoToService getGoToService() {
		return gotoService;
	}

	SymbolProvider getSymbolProvider() {
		return symProvider;
	}

	ReferenceProvider getReferenceProvider() {
		return refProvider;
	}

	void openSymbolProvider() {
		if (symProvider != null) {
			symProvider.open();
		}
	}

	void closeReferenceProvider() {
		if (refProvider != null) {
			refProvider.closeComponent();
		}
	}

	private void createSymActions() {
		String popupGroup = "1";

		openRefsAction = new DockingAction("Symbol References", getName(), KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				refProvider.open();
				refProvider.setCurrentSymbol(symProvider.getCurrentSymbol());
			}
		};
		ImageIcon icon = ResourceManager.loadImage("images/table_go.png");
		openRefsAction.setPopupMenuData(
			new MenuData(new String[] { "Symbol References" }, icon, popupGroup));
		openRefsAction.setToolBarData(new ToolBarData(icon));

		openRefsAction.setDescription("Display Symbol References");
		tool.addLocalAction(symProvider, openRefsAction);

		deleteAction = new DockingAction("Delete Symbols", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				symProvider.deleteSymbols();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				GhidraTable table = symProvider.getTable();
				return table.getSelectedRowCount() > 0;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};

		icon = ResourceManager.loadImage("images/edit-delete.png");
		String deleteGroup = "3"; // put in a group after the others
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, icon, deleteGroup));
		deleteAction.setToolBarData(new ToolBarData(icon));
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		deleteAction.setDescription("Delete Selected Symbols");
		deleteAction.setEnabled(false);
		tool.addLocalAction(symProvider, deleteAction);

		DockingAction editExternalLocationAction = new EditExternalLocationAction(this);
		tool.addLocalAction(symProvider, editExternalLocationAction);

		makeSelectionAction = new MakeProgramSelectionAction(this, symProvider.getTable());
		makeSelectionAction.getPopupMenuData().setMenuGroup(popupGroup);

		tool.addLocalAction(symProvider, makeSelectionAction);

		setFilterAction = new DockingAction("Set Filter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				symProvider.setFilter();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		icon = Icons.CONFIGURE_FILTER_ICON;
		setFilterAction.setToolBarData(new ToolBarData(icon));

		setFilterAction.setDescription("Configure Symbol Filter");
		tool.addLocalAction(symProvider, setFilterAction);

		// override the SelectionNavigationAction to handle both tables that this plugin uses
		DockingAction selectionNavigationAction =
			new SelectionNavigationAction(this, symProvider.getTable()) {

				@Override
				protected void toggleSelectionListening(boolean listen) {
					super.toggleSelectionListening(listen);
					refProvider.getTable().setNavigateOnSelectionEnabled(listen);
				}
			};
		tool.addLocalAction(symProvider, selectionNavigationAction);

		String pinnedPopupGroup = "2"; // second group
		DockingAction setPinnedAction = new PinSymbolAction(getName(), pinnedPopupGroup);
		tool.addAction(setPinnedAction);

		DockingAction clearPinnedAction = new ClearPinSymbolAction(getName(), pinnedPopupGroup);
		tool.addAction(clearPinnedAction);
	}

	private void createRefActions() {
		referencesToAction = new ToggleDockingAction("References To", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (referencesToAction.isSelected()) {
					refProvider.showReferencesTo();
					referencesToAction.setSelected(true);
					instructionsFromAction.setSelected(false);
					dataFromAction.setSelected(false);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(referencesToAction);
				}
			}
		};
		referencesToAction.setDescription("References To");
		referencesToAction.setSelected(true);
		referencesToAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/references_to.gif"), null));

		tool.addLocalAction(refProvider, referencesToAction);

		instructionsFromAction = new ToggleDockingAction("Instruction References From", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (instructionsFromAction.isSelected()) {
					refProvider.showInstructionsFrom();
					referencesToAction.setSelected(false);
					instructionsFromAction.setSelected(true);
					dataFromAction.setSelected(false);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(instructionsFromAction);
				}
			}
		};
		instructionsFromAction.setDescription("Instructions From");
		instructionsFromAction.setSelected(false);
		instructionsFromAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/I.gif"), null));

		tool.addLocalAction(refProvider, instructionsFromAction);

		dataFromAction = new ToggleDockingAction("Data References From", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (dataFromAction.isSelected()) {
					refProvider.showDataFrom();
					referencesToAction.setSelected(false);
					instructionsFromAction.setSelected(false);
					dataFromAction.setSelected(true);
				}
				// don't let the user de-click the button, since these buttons change in
				// response to each other, like a javax.swing.ButtonGroup set
				else {
					reselectAction(dataFromAction);
				}
			}
		};
		dataFromAction.setDescription("Data From");
		dataFromAction.setSelected(false);
		dataFromAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/D.gif"), null));

		tool.addLocalAction(refProvider, dataFromAction);
	}

	// a HACK to make the given action the selected action
	private void reselectAction(ToggleDockingAction action) {
		// We must reselect the action and trigger the proper painting of its button.  We do this
		// by indirectly triggering property change events, which will not happen if we do not
		// change the state of the action.  So, the action is given to us in a selected state and
		// we must leave it in a selected state while trigger a property change, which is done
		// by toggling the state
		action.setSelected(false);
		action.setSelected(true);
	}
}
