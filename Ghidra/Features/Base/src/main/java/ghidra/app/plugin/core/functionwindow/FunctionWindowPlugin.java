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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.functioncompare.actions.CompareFunctionsFromFunctionTableAction;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;

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
public class FunctionWindowPlugin extends ProgramPlugin {

	private DockingAction selectAction;
	private DockingAction compareFunctionsAction;
	private FunctionWindowProvider provider;
	private SwingUpdateManager swingMgr;
	private DomainObjectListener domainObjectListener;

	public FunctionWindowPlugin(PluginTool tool) {
		super(tool);

		swingMgr = new SwingUpdateManager(1000, () -> provider.reload());
	}

	@Override
	public void init() {
		super.init();
		provider = new FunctionWindowProvider(this);
		domainObjectListener = createDomainObjectListener();
		createActions();

		/**
		 * Kicks the tool actions to set the proper enablement when selection changes
		 * on the function table
		 */
		provider.getTable().getSelectionModel().addListSelectionListener(x -> {
			tool.contextChanged(provider);
		});
	}

	@Override
	public void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(domainObjectListener);
		}
		swingMgr.dispose();
		if (provider != null) {
			provider.dispose();
		}
		super.dispose();
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == FunctionComparisonService.class) {
			compareFunctionsAction = new CompareFunctionsFromFunctionTableAction(tool, getName());
			tool.addLocalAction(provider, compareFunctionsAction);
			tool.contextChanged(provider);
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == FunctionComparisonService.class) {
			tool.removeLocalAction(provider, compareFunctionsAction);
			compareFunctionsAction = null;
		}
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.ignoreWhen(() -> !provider.isVisible())
			.any(RESTORED, MEMORY_BLOCK_MOVED, MEMORY_BLOCK_REMOVED).terminate(provider::reload)
			.any(CODE_ADDED, CODE_REMOVED).call(swingMgr::update)
			.with(ProgramChangeRecord.class)
				.each(FUNCTION_ADDED).call(this::functionAdded)
				.each(FUNCTION_REMOVED).call(this::functionRemoved)
				.each(FUNCTION_CHANGED).call(this::functionChanged)
				.each(SYMBOL_ADDED, SYMBOL_PRIMARY_STATE_CHANGED).call(this::symbolChanged)
				.each(SYMBOL_RENAMED).call(this::symbolRenamed)
			.build();
		// @formatter:on
	}

	private void functionAdded(ProgramChangeRecord rec) {
		Function function = (Function) rec.getObject();
		provider.functionAdded(function);
	}

	private void functionRemoved(ProgramChangeRecord rec) {
		Function function = (Function) rec.getObject();
		if (function != null) {
			provider.functionRemoved(function);
		}
	}

	private void functionChanged(ProgramChangeRecord rec) {
		Function function = (Function) rec.getObject();
		provider.update(function);
	}

	private void symbolChanged(ProgramChangeRecord rec) {
		Symbol sym = (Symbol) rec.getNewValue();
		Address addr = sym.getAddress();
		Function function = currentProgram.getListing().getFunctionAt(addr);
		if (function != null) {
			provider.update(function);
		}
	}

	private void symbolRenamed(ProgramChangeRecord rec) {
		Symbol sym = (Symbol) rec.getObject();
		Address addr = sym.getAddress();
		Function function = currentProgram.getListing().getFunctionAt(addr);
		if (function != null) {
			provider.update(function);
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(domainObjectListener);
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(domainObjectListener);
		provider.programClosed();
	}

	Program getProgram() {
		return currentProgram;
	}

	private void createActions() {
		DockingAction action = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, action);

		selectAction = new MakeProgramSelectionAction(this, provider.getTable());
		tool.addLocalAction(provider, selectAction);

		// note that the compare functions action is only added when the compare functions service
		// is added to the tool
	}

	void showFunctions() {
		provider.showFunctions();
	}

}
