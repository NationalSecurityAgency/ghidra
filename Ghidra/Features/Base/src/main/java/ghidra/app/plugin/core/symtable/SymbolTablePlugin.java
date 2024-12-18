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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.awt.Cursor;
import java.awt.event.KeyEvent;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import generic.theme.GIcon;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.symboltree.actions.*;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.GoToService;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;
import resources.Icons;

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
public class SymbolTablePlugin extends Plugin {

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

	private DomainObjectListener domainObjectListener = createDomainObjectListener();

	/**
	 * A worker that will process domain object change event work off of the Swing thread.  This 
	 * solves the issue of db lock contention that can happen during analysis while this class
	 * attempts to get symbols from the db while processing a flurry of domain events.
	 */
	private Worker domainObjectWorker = Worker.createGuiWorker();

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

		domainObjectWorker.dispose();
		if (symProvider != null) {
			symProvider.dispose();
			symProvider = null;
		}
		if (refProvider != null) {
			refProvider.dispose();
			refProvider = null;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(domainObjectListener);
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
				oldProg.removeListener(domainObjectListener);
				domainObjectWorker.clearAllJobs();
				symProvider.setProgram(null, inspector);
				refProvider.setProgram(null, inspector);
				tool.contextChanged(symProvider);
			}
			currentProgram = newProg;
			if (newProg != null) {
				currentProgram.addListener(domainObjectListener);
				symProvider.setProgram(currentProgram, inspector);
				refProvider.setProgram(currentProgram, inspector);
			}

			tool.contextChanged(symProvider);
		}
	}

	boolean isBusy() {
		return domainObjectWorker.isBusy() || symProvider.isBusy() || refProvider.isBusy();
	}

	private void reload() {
		domainObjectWorker.clearAllJobs();
		symProvider.reload();
		refProvider.reload();
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.ignoreWhen(() -> !symProvider.isVisible() && !refProvider.isVisible())
			.any(RESTORED, MEMORY_BLOCK_ADDED, MEMORY_BLOCK_REMOVED)
				.terminate(this::reload)
			.with(ProgramChangeRecord.class)
				.each(CODE_ADDED, CODE_REMOVED)
					.call(this::codeAddedRemoved)
				.each(SYMBOL_ADDED)
					.call(this::symbolAdded)
				.each(SYMBOL_REMOVED)
					.call(this::symbolRemoved)
				.each(SYMBOL_RENAMED, SYMBOL_SCOPE_CHANGED, SYMBOL_DATA_CHANGED)
					.call(this::symbolChanged)
				.each(SYMBOL_SOURCE_CHANGED)
					.call(this::symbolSourceChanged)
				.each(SYMBOL_PRIMARY_STATE_CHANGED)
					.call(this::symbolPrimaryStateChanged)
				.each(REFERENCE_ADDED)
					.call(this::referenceAdded)
				.each(REFERENCE_REMOVED)
					.call(this::referenceRemoved)
				.each(EXTERNAL_ENTRY_ADDED, EXTERNAL_ENTRY_REMOVED)
					.call(this::extenalEntryAddedRemoved)
			.build();
		// @formatter:on
	}

	private void codeAddedRemoved(ProgramChangeRecord rec) {
		if (rec.getNewValue() instanceof Data) {
			domainObjectWorker.schedule(new CodeAddedRemoveJob(currentProgram, rec.getStart()));
		}
	}

	private void symbolAdded(ProgramChangeRecord rec) {
		// NOTE: DOCR_SYMBOL_ADDED events are never generated for reference-based 
		// dynamic label symbols.  Reference events must be used to check for existence 
		// of a dynamic label symbol.
		Symbol symbol = (Symbol) rec.getNewValue();
		domainObjectWorker.schedule(new SymbolAddedJob(currentProgram, symbol));
	}

	private void symbolRemoved(ProgramChangeRecord rec) {
		Address removeAddr = rec.getStart();
		Long symbolID = (Long) rec.getNewValue();
		domainObjectWorker.schedule(new SymbolRemovedJob(currentProgram, removeAddr, symbolID));
	}

	private void symbolChanged(ProgramChangeRecord rec) {
		Symbol symbol = (Symbol) rec.getObject();
		domainObjectWorker.schedule(new SymbolChangedJob(currentProgram, symbol));
	}

	private void symbolSourceChanged(ProgramChangeRecord rec) {
		Symbol symbol = (Symbol) rec.getObject();
		domainObjectWorker.schedule(new SymbolSourceChangedJob(currentProgram, symbol));
	}

	private void symbolPrimaryStateChanged(ProgramChangeRecord rec) {
		Symbol symbol = (Symbol) rec.getNewValue();
		Symbol oldPrimarySymbol = (Symbol) rec.getOldValue();
		domainObjectWorker
				.schedule(new SymbolSetAsPrimaryJob(currentProgram, symbol, oldPrimarySymbol));
	}

	private void referenceAdded(ProgramChangeRecord rec) {
		Reference ref = (Reference) rec.getObject();
		domainObjectWorker.schedule(new ReferenceAddedJob(currentProgram, ref));
	}

	private void referenceRemoved(ProgramChangeRecord rec) {
		Reference ref = (Reference) rec.getObject();
		domainObjectWorker.schedule(new ReferenceRemovedJob(currentProgram, ref));
	}

	private void extenalEntryAddedRemoved(ProgramChangeRecord rec) {
		Address address = rec.getStart();
		domainObjectWorker.schedule(new ExternalEntryChangedJob(currentProgram, address));
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

	void symbolProviderClosed() {
		domainObjectWorker.clearAllJobs();
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
		Icon icon = new GIcon("icon.plugin.symboltable.referencetable.provider");
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

		icon = Icons.DELETE_ICON;
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

		CreateSymbolTableAction tableAction = new CreateSymbolTableAction(this);
		tableAction.getPopupMenuData().setMenuGroup(popupGroup);
		tool.addLocalAction(symProvider, tableAction);
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
			new ToolBarData(new GIcon("icon.plugin.symboltable.references.to"), null));

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
			new ToolBarData(new GIcon("icon.plugin.symboltable.instructions.from"), null));

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
			new ToolBarData(new GIcon("icon.plugin.symboltable.data.from"), null));

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

//==================================================================================================
// Table Update Jobs
//==================================================================================================

	private abstract class AbstractSymbolUpdateJob extends Job {

		protected Program program;

		AbstractSymbolUpdateJob(Program program) {
			this.program = program;
		}

		@Override
		public final void run(TaskMonitor taskMonitor) {
			if (program != currentProgram) {
				return;
			}
			doRun();
		}

		protected abstract void doRun();
	}

	private class CodeAddedRemoveJob extends AbstractSymbolUpdateJob {

		private Address start;

		CodeAddedRemoveJob(Program program, Address start) {
			super(program);
			this.start = start;
		}

		@Override
		protected void doRun() {

			if (!symProvider.isShowingDynamicSymbols()) {
				return;
			}

			// Note: this code *should* be checking the entire address range to handle the case 
			//       where large address range was cleared.   This implementation will handle the
			//       case where individual code units are cleared.  This feature has been this way
			//       for many years.   The assumption is that most users are not showing dynamic
			//       symbols often, especially not when performing analysis or clearing large 
			//       address ranges.    Checking each address of the changed range is very slow.
			//       This code will need to be updated in the future if we decide updating the
			//       dynamic symbols in the symbol table is worth the cost.  For now, if the table
			//       becomes out-of-date, then user can simply close and re-open the table to 
			//       trigger an update.
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			Symbol symbol = symbolTable.getPrimarySymbol(start);
			if (symbol != null && symbol.isDynamic()) {
				symProvider.symbolChanged(symbol);
				refProvider.symbolChanged(symbol);
			}
		}
	}

	private class SymbolAddedJob extends AbstractSymbolUpdateJob {

		private Symbol symbol;

		SymbolAddedJob(Program program, Symbol symbol) {
			super(program);
			this.symbol = symbol;
		}

		@Override
		protected void doRun() {
			symProvider.symbolAdded(symbol);
			refProvider.symbolAdded(symbol);
		}
	}

	private class SymbolRemovedJob extends AbstractSymbolUpdateJob {

		private long symbolId;
		private Address address;

		SymbolRemovedJob(Program program, Address address, long symbolId) {
			super(program);
			this.address = address;
			this.symbolId = symbolId;
		}

		@Override
		protected void doRun() {
			symProvider.symbolRemoved(symbolId);
			refProvider.symbolRemoved(symbolId);

			if (!symProvider.isShowingDynamicSymbols()) {
				return;
			}

			SymbolTable symbolTable = currentProgram.getSymbolTable();
			Symbol primaryAtRemove = symbolTable.getPrimarySymbol(address);
			if (primaryAtRemove != null && primaryAtRemove.isDynamic()) {
				// 
				symProvider.symbolChanged(primaryAtRemove);
				refProvider.symbolChanged(primaryAtRemove);
			}
		}
	}

	private class SymbolChangedJob extends AbstractSymbolUpdateJob {

		private Symbol symbol;

		SymbolChangedJob(Program program, Symbol symbol) {
			super(program);
			this.symbol = symbol;
		}

		@Override
		protected void doRun() {
			symProvider.symbolChanged(symbol);
			refProvider.symbolChanged(symbol);
		}
	}

	private class SymbolSourceChangedJob extends AbstractSymbolUpdateJob {

		private Symbol symbol;

		SymbolSourceChangedJob(Program program, Symbol symbol) {
			super(program);
			this.symbol = symbol;
		}

		@Override
		protected void doRun() {
			symProvider.symbolChanged(symbol);
		}
	}

	private class SymbolSetAsPrimaryJob extends AbstractSymbolUpdateJob {

		private Symbol symbol;
		private Symbol oldPrimarySymbol;

		SymbolSetAsPrimaryJob(Program program, Symbol symbol, Symbol oldPrimarySymbol) {
			super(program);
			this.symbol = symbol;
			this.oldPrimarySymbol = oldPrimarySymbol;
		}

		@Override
		protected void doRun() {

			symProvider.symbolChanged(symbol);
			if (oldPrimarySymbol != null) {
				symProvider.symbolChanged(oldPrimarySymbol);
			}
		}
	}

	private class ReferenceAddedJob extends AbstractSymbolUpdateJob {

		private Reference reference;

		ReferenceAddedJob(Program program, Reference reference) {
			super(program);
			this.reference = reference;
		}

		@Override
		protected void doRun() {

			Address toAddr = reference.getToAddress();
			boolean isValid = toAddr.isMemoryAddress() || toAddr.isExternalAddress();
			if (!isValid) {
				return;
			}

			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.getSymbol(reference);
			if (symbol == null) {
				return;
			}

			if (!symbol.isDynamic() || symProvider.isShowingDynamicSymbols()) {
				symProvider.symbolChanged(symbol);
				refProvider.symbolChanged(symbol);
			}
		}
	}

	private class ReferenceRemovedJob extends AbstractSymbolUpdateJob {

		private Reference reference;

		ReferenceRemovedJob(Program program, Reference reference) {
			super(program);
			this.reference = reference;
		}

		@Override
		protected void doRun() {

			Address toAddr = reference.getToAddress();
			boolean isValid = toAddr.isMemoryAddress() || toAddr.isExternalAddress();
			if (!isValid) {
				return;
			}

			SymbolTable symbolTable = program.getSymbolTable();
			Symbol symbol = symbolTable.getSymbol(reference);
			if (symbol != null) {
				if (!symbol.isDynamic() || symProvider.isShowingDynamicSymbols()) {
					symProvider.symbolChanged(symbol);
					refProvider.symbolChanged(symbol);
				}
			}
			else if (toAddr.isMemoryAddress() && symProvider.isShowingDynamicSymbols()) {
				long dynamicSymbolId = symbolTable.getDynamicSymbolID(toAddr);
				symProvider.symbolRemoved(dynamicSymbolId);
				refProvider.symbolRemoved(dynamicSymbolId);
			}
		}
	}

	private class ExternalEntryChangedJob extends AbstractSymbolUpdateJob {

		private Address address;

		ExternalEntryChangedJob(Program program, Address address) {
			super(program);
			this.address = address;
		}

		@Override
		protected void doRun() {

			SymbolTable symbolTable = program.getSymbolTable();
			Symbol[] symbols = symbolTable.getSymbols(address);
			for (Symbol element : symbols) {
				symProvider.symbolChanged(element);
				refProvider.symbolChanged(element);
			}
		}
	}

}
