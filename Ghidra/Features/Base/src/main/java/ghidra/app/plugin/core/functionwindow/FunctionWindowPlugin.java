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
package ghidra.app.plugin.core.functionwindow;

import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProviderManager;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Function Viewer",
	description = "Provides a window that displays the list of functions in the program.",
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class FunctionWindowPlugin extends ProgramPlugin
		implements DomainObjectListener, OptionsChangeListener {

	private DockingAction selectAction;
	private DockingAction compareAction;
	private FunctionWindowProvider provider;
	private SwingUpdateManager swingMgr;
	private FunctionComparisonProviderManager functionComparisonManager;

	///////////////////////////////////////////////////////////

	public FunctionWindowPlugin(PluginTool tool) {
		super(tool, true, false);

		functionComparisonManager = new FunctionComparisonProviderManager(this);

		swingMgr = new SwingUpdateManager(1000, new Runnable() {
			@Override
			public void run() {
				provider.reload();
			}
		});

	}

	@Override
	public void init() {
		super.init();

		provider = new FunctionWindowProvider(this);
		createActions();
	}

	@Override
	public void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		swingMgr.dispose();
		provider.dispose();
		super.dispose();
	}

	////////////////////////////////////////////////////////////////////////////
	//
	//  Implementation of DomainObjectListener
	//
	////////////////////////////////////////////////////////////////////////////

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			functionComparisonManager.domainObjectRestored(ev);
		}

		if (!provider.isVisible()) {
			return;
		}

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED)) {
			provider.reload();
			return;
		}

		for (int i = 0; i < ev.numRecords(); ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);

			int eventType = doRecord.getEventType();

			switch (eventType) {
				case ChangeManager.DOCR_CODE_ADDED:
				case ChangeManager.DOCR_CODE_REMOVED:
					swingMgr.update();
					break;

				case ChangeManager.DOCR_FUNCTION_ADDED:
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Function function = (Function) rec.getObject();
					provider.functionAdded(function);
					break;
				case ChangeManager.DOCR_FUNCTION_REMOVED:
					rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					function = (Function) rec.getObject();
					if (function != null) {
						provider.functionRemoved(function);
					}
					break;
				case ChangeManager.DOCR_FUNCTION_CHANGED:
					rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					function = (Function) rec.getObject();
					provider.update(function);
					break;
				case ChangeManager.DOCR_SYMBOL_ADDED:
				case ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY:
					rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Symbol sym = (Symbol) rec.getNewValue();
					Address addr = sym.getAddress();
					function = currentProgram.getListing().getFunctionAt(addr);
					if (function != null) {
						provider.update(function);
					}
					break;
				case ChangeManager.DOCR_SYMBOL_RENAMED:
					rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					sym = (Symbol) rec.getObject();
					addr = sym.getAddress();
					function = currentProgram.getListing().getFunctionAt(addr);
					if (function != null) {
						provider.update(function);
					}
					break;
			/*case ChangeManager.DOCR_SYMBOL_REMOVED:
				rec = (ProgramChangeRecord)ev.getChangeRecord(i);
				addr = (Address)rec.getObject();
				function = currentProgram.getListing().getFunctionAt(addr);
				if (function != null) {
					provider.functionChanged(function);
				}
				break;*/
			}
		}
	}

	////////////////////////////////////////////////////////////////////////////

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.programClosed();
	}

	////////////////////////////////////////////////////////////////////////////

	Program getProgram() {
		return currentProgram;
	}

	////////////////////////////////////////////////////////////////////////////

	/**
	 * Create the action objects for this plugin.
	 */
	private void createActions() {
		addSelectAction();
		addCompareAction();

		DockingAction action = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, action);
	}

	private void addSelectAction() {
		selectAction = new DockingAction("Make Selection", getName(), false) {
			@Override
			public void actionPerformed(ActionContext context) {
				selectFunctions(provider.selectFunctions());
			}
		};
		selectAction.setEnabled(false);
		ImageIcon icon = ResourceManager.loadImage("images/text_align_justify.png");
		selectAction.setPopupMenuData(new MenuData(new String[] { "Make Selection" }, icon));
		selectAction.setDescription("Selects currently selected function(s) in table");
		selectAction.setToolBarData(new ToolBarData(icon));

		installDummyAction(selectAction);

		tool.addLocalAction(provider, selectAction);
	}

	private void addCompareAction() {
		compareAction = new DockingAction("Compare Selected Functions", getName(), false) {
			@Override
			public void actionPerformed(ActionContext context) {
				compareSelectedFunctions();
			}
		};
		compareAction.setEnabled(false);
		ImageIcon icon = ResourceManager.loadImage("images/page_white_c.png");
		compareAction.setPopupMenuData(new MenuData(new String[] { "Compare Functions" }, icon));
		compareAction.setDescription("Compares the currently selected function(s) in the table.");
		compareAction.setToolBarData(new ToolBarData(icon));

		installDummyAction(compareAction);

		tool.addLocalAction(provider, compareAction);
	}

	private void installDummyAction(DockingAction action) {
		DummyKeyBindingsOptionsAction dummyAction =
			new DummyKeyBindingsOptionsAction(action.getName(), null);
		tool.addAction(dummyAction);

		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		options.addOptionsChangeListener(this);

		KeyStroke keyStroke = options.getKeyStroke(dummyAction.getFullName(), null);
		if (keyStroke != null) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
		if (optionName.startsWith(selectAction.getName())) {
			KeyStroke keyStroke = (KeyStroke) newValue;
			selectAction.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		if (optionName.startsWith(compareAction.getName())) {
			KeyStroke keyStroke = (KeyStroke) newValue;
			compareAction.setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	void setActionsEnabled(boolean enabled) {
		selectAction.setEnabled(enabled);
		compareAction.setEnabled(enabled);
	}

	void showFunctions() {
		provider.showFunctions();
	}

	private void selectFunctions(ProgramSelection selection) {
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", selection, currentProgram);
		firePluginEvent(pspe);
	}

	private FunctionComparisonProvider compareSelectedFunctions() {
		Function[] functions = getSelectedFunctions();
		if (functions.length < 2) {
			Msg.showError(this, provider.getComponent(), "Compare Selected Functions",
				"Select two or more rows in the table indicating functions to compare.");
			return null;
		}
		return functionComparisonManager.showFunctionComparisonProvider(functions);
	}

	/**
	 * Gets the functions that are currently selected in the table.
	 * @return the selected functions
	 */
	private Function[] getSelectedFunctions() {
		GhidraTable table = provider.getTable();
		int[] selectedRows = table.getSelectedRows();
		Function[] functions = new Function[selectedRows.length];
		FunctionTableModel model = provider.getModel();
		Program program = model.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		List<FunctionRowObject> functionRowObjects = model.getRowObjects(selectedRows);
		int index = 0;
		for (FunctionRowObject functionRowObject : functionRowObjects) {
			long key = functionRowObject.getKey();
			functions[index++] = functionManager.getFunction(key);
		}
		return functions;
	}

	@Override
	protected void programClosed(Program program) {
		functionComparisonManager.closeProviders(program);
	}
}
