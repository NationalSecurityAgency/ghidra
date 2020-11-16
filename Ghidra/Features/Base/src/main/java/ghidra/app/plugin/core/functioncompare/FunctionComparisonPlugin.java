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
package ghidra.app.plugin.core.functioncompare;

import java.util.Set;
import java.util.function.Supplier;

import docking.ComponentProviderActivationListener;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.functioncompare.actions.CompareFunctionsAction;
import ghidra.app.plugin.core.functioncompare.actions.CompareFunctionsFromListingAction;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Swing;

/**
 * Allows users to create function comparisons that are displayed
 * side-by-side in a provider. Comparisons can be initiated via the listing 
 * or function table and are displayed in a {@link FunctionComparisonProvider}.
 * <p>
 * The underlying data backing the comparison provider is managed by the
 * {@link FunctionComparisonService}. 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.DIFF,
	shortDescription = "Compare Functions",
	description = "Allows users to compare two or more functions",
	servicesProvided = { FunctionComparisonService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class, ProgramActivatedPluginEvent.class,
		ProgramClosedPluginEvent.class }
)
//@formatter:on
public class FunctionComparisonPlugin extends ProgramPlugin
		implements DomainObjectListener, FunctionComparisonService {

	static final String MENU_PULLRIGHT = "CompareFunctions";
	static final String POPUP_MENU_GROUP = "CompareFunction";

	private FunctionComparisonProviderManager functionComparisonManager;

	/**
	 * Constructor
	 * 
	 * @param tool the tool that owns this plugin
	 */
	public FunctionComparisonPlugin(PluginTool tool) {
		super(tool, true, true);
		functionComparisonManager = new FunctionComparisonProviderManager(this);
	}

	@Override
	protected void init() {
		CompareFunctionsAction compareFunctionsAction =
			new CompareFunctionsFromListingAction(tool, getName());
		tool.addAction(compareFunctionsAction);
	}

	@Override
	public void dispose() {
		functionComparisonManager.dispose();
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programClosed(Program program) {
		functionComparisonManager.closeProviders(program);
		program.removeListener(this);
	}

	/**
	 * Overridden to listen for two event types:
	 * <li>Object Restored: In the event of a redo/undo that affects a function
	 * being shown in the comparison provider, this will allow tell the provider
	 * to reload</li>
	 * <li>Object Removed: If a function is deleted, this will tell the provider
	 * to purge it from the view</li>
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		for (int i = 0; i < ev.numRecords(); ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);

			int eventType = doRecord.getEventType();

			switch (eventType) {
				case DomainObject.DO_OBJECT_RESTORED:
					functionComparisonManager.domainObjectRestored(ev);
					break;
				case ChangeManager.DOCR_FUNCTION_REMOVED:
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Function function = (Function) rec.getObject();
					if (function != null) {
						removeFunction(function);
					}
					break;
			}
		}
	}

	private void runOnSwingNonBlocking(Runnable r) {
		Swing.runIfSwingOrRunLater(r);
	}

	private FunctionComparisonProvider getFromSwingBlocking(
			Supplier<FunctionComparisonProvider> comparer) {

		if (Swing.isSwingThread()) {
			return comparer.get();
		}

		return Swing.runNow(comparer);
	}

//==================================================================================================
// Service Methods
//==================================================================================================	

	@Override
	public void addFunctionComparisonProviderListener(
			ComponentProviderActivationListener listener) {
		runOnSwingNonBlocking(() -> functionComparisonManager.addProviderListener(listener));
	}

	@Override
	public void removeFunctionComparisonProviderListener(
			ComponentProviderActivationListener listener) {
		runOnSwingNonBlocking(() -> functionComparisonManager.removeProviderListener(listener));
	}

	@Override
	public void removeFunction(Function function) {
		runOnSwingNonBlocking(() -> functionComparisonManager.removeFunction(function));
	}

	@Override
	public void removeFunction(Function function, FunctionComparisonProvider provider) {
		runOnSwingNonBlocking(() -> functionComparisonManager.removeFunction(function, provider));
	}

	@Override
	public FunctionComparisonProvider compareFunctions(Function source,
			Function target) {
		return getFromSwingBlocking(
			() -> functionComparisonManager.compareFunctions(source, target));
	}

	@Override
	public FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		return getFromSwingBlocking(() -> functionComparisonManager.compareFunctions(functions));
	}

	@Override
	public void compareFunctions(Set<Function> functions, FunctionComparisonProvider provider) {
		runOnSwingNonBlocking(
			() -> functionComparisonManager.compareFunctions(functions, provider));
	}

	@Override
	public void compareFunctions(Function source, Function target,
			FunctionComparisonProvider provider) {
		runOnSwingNonBlocking(
			() -> functionComparisonManager.compareFunctions(source, target, provider));
	}
}
