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
package ghidra.features.codecompare.plugin;

import java.util.*;
import java.util.function.Consumer;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.FunctionSupplierContext;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.features.base.codecompare.model.DefaultFunctionComparisonModel;
import ghidra.features.base.codecompare.model.FunctionComparisonModel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import utility.function.Callback;

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
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Compare Functions",
	description = "Allows users to compare two or more functions",
	servicesProvided = { FunctionComparisonService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class, ProgramActivatedPluginEvent.class,
		ProgramClosedPluginEvent.class }
)
//@formatter:on
public class FunctionComparisonPlugin extends ProgramPlugin
		implements DomainObjectListener, FunctionComparisonService {

	// Keep a stack of recently added providers so that the "add to comparison" service methods
	// can easily add to the last created provider.
	private Deque<FunctionComparisonProvider> providers = new ArrayDeque<>();

	public FunctionComparisonPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	@Override
	public void dispose() {
		foreEachProvider(p -> p.closeComponent());
	}

	@Override
	protected void programOpened(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programClosed(Program program) {
		program.removeListener(this);
		foreEachProvider(p -> p.programClosed(program));
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

			EventType eventType = doRecord.getEventType();
			if (eventType == DomainObjectEvent.RESTORED) {
				domainObjectRestored((Program) ev.getSource());
			}
			else if (eventType == ProgramEvent.FUNCTION_REMOVED) {
				ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
				Function function = (Function) rec.getObject();
				if (function != null) {
					removeFunction(function);
				}
			}
		}
	}

	void providerClosed(FunctionComparisonProvider provider) {
		providers.remove(provider);
	}

	void removeFunction(Function function) {
		Swing.runIfSwingOrRunLater(() -> doRemoveFunction(function));
	}

	private void foreEachProvider(Consumer<FunctionComparisonProvider> c) {
		// copy needed because this may cause callbacks to remove a provider from our list
		List<FunctionComparisonProvider> localCopy = new ArrayList<>(providers);
		localCopy.forEach(c);

	}

	private void domainObjectRestored(Program program) {
		foreEachProvider(p -> p.programRestored(program));
	}

	private void createActions() {
		new ActionBuilder("Compare Functions", getName())
				.description("Create Function Comparison")
				.popupMenuPath("Compare Function(s)")
				.helpLocation(new HelpLocation("FunctionComparison", "Function_Comparison"))
				.popupMenuGroup("Functions", "Z1")
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(c -> c.hasFunctions())
				.onAction(c -> createComparison(c.getFunctions()))
				.buildAndInstall(tool);

		new ActionBuilder("Add To Last Function Comparison", getName())
				.description("Add the selected function(s) to the last Function Comparison window")
				.popupMenuPath("Add To Last Comparison")
				.helpLocation(new HelpLocation("FunctionComparison", "Function_Comparison_Add_To"))
				.popupMenuGroup("Functions", "Z2")
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(c -> c.hasFunctions())
				.onAction(c -> addToComparison(c.getFunctions()))
				.buildAndInstall(tool);
	}

	private void doRemoveFunction(Function function) {
		foreEachProvider(p -> p.getModel().removeFunction(function));
	}

	private FunctionComparisonProvider createProvider(FunctionComparisonModel model) {
		return createProvider(model, null);
	}

	private FunctionComparisonProvider createProvider(FunctionComparisonModel model,
			Callback closeListener) {
		FunctionComparisonProvider provider =
			new FunctionComparisonProvider(this, model, closeListener);

		// insert at the top so the last created provider is first when searching for a provider
		providers.addFirst(provider);
		return provider;
	}

	private FunctionComparisonProvider findLastDefaultProviderModel() {
		for (FunctionComparisonProvider provider : providers) {
			if (provider.getModel() instanceof DefaultFunctionComparisonModel) {
				return provider;
			}
		}
		return null;
	}

//==================================================================================================
// Service Methods
//==================================================================================================	
	@Override
	public void createComparison(Collection<Function> functions) {
		if (functions.isEmpty()) {
			return;
		}
		DefaultFunctionComparisonModel model = new DefaultFunctionComparisonModel(functions);
		Swing.runLater(() -> createProvider(model));
	}

	@Override
	public void createComparison(Function left, Function right) {
		DefaultFunctionComparisonModel model = new DefaultFunctionComparisonModel(left, right);
		Swing.runLater(() -> createProvider(model));
	}

	@Override
	public void addToComparison(Collection<Function> functions) {
		FunctionComparisonProvider lastProvider = findLastDefaultProviderModel();
		if (lastProvider == null) {
			createComparison(functions);
		}
		else {
			DefaultFunctionComparisonModel model =
				(DefaultFunctionComparisonModel) lastProvider.getModel();
			Swing.runLater(() -> model.addFunctions(functions));
		}
	}

	@Override
	public void addToComparison(Function function) {
		addToComparison(Arrays.asList(function));
	}

	@Override
	public void createCustomComparison(FunctionComparisonModel model, Callback closeListener) {
		Swing.runLater(() -> createProvider(model, closeListener));
	}

}
