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
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.FunctionComparisonService;
import ghidra.features.base.codecompare.model.AnyToAnyFunctionComparisonModel;
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

	private Set<FunctionComparisonProvider> providers = new HashSet<>();
	private FunctionComparisonProvider lastActiveProvider;

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
		if (lastActiveProvider == provider) {
			lastActiveProvider = null;
		}
	}

	void removeFunction(Function function) {
		Swing.runIfSwingOrRunLater(() -> doRemoveFunction(function));
	}

	void providerActivated(FunctionComparisonProvider provider) {
		if (provider.supportsAddingFunctions()) {
			lastActiveProvider = provider;
		}
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

		HelpLocation help = new HelpLocation("FunctionComparison", "Function_Comparison_Actions");

		new ActionBuilder("Function Comparison", getName())
				.popupMenuPath("Compare Function(s)")
				.popupMenuGroup("Functions", "Z1")
				.description("Adds the selected function(s) to the current comparison window.")
				.helpLocation(help)
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(c -> !isListing(c) && c.hasFunctions())
				.onAction(c -> addToComparison(c.getFunctions()))
				.buildAndInstall(tool);

		// same action as above, but with an extra pull right when shown in the listing
		new ActionBuilder("Function Comparison (Listing)", getName())
				.popupMenuPath("Function", "Compare Function(s)")
				.popupMenuGroup("Functions", "Z1")
				.description("Adds the selected function(s) to the current comparison window.")
				.helpLocation(help)
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(c -> isListing(c) && c.hasFunctions())
				.onAction(c -> addToComparison(c.getFunctions()))
				.buildAndInstall(tool);

		new ActionBuilder("New Function Comparison", getName())
				.popupMenuPath("Compare in New Window")
				.popupMenuGroup("Functions", "Z2")
				.description("Compare the selected function(s) in a new comparison window.")
				.helpLocation(help)
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(
					c -> !isListing(c) && c.hasFunctions() && hasExistingComparison())
				.onAction(c -> createComparison(c.getFunctions()))
				.buildAndInstall(tool);

		// same action as above, but with an extra pull right when shown in the listing
		new ActionBuilder("New Function Comparison (Listing)", getName())
				.popupMenuPath("Function", "Compare in New Window")
				.popupMenuGroup("Functions", "Z2")
				.description("Compare the selected function(s) in a new comparison window.")
				.helpLocation(help)
				.withContext(FunctionSupplierContext.class)
				.enabledWhen(c -> isListing(c) && c.hasFunctions() && hasExistingComparison())
				.onAction(c -> createComparison(c.getFunctions()))
				.buildAndInstall(tool);

	}

	private boolean isListing(FunctionSupplierContext context) {
		return context instanceof ListingActionContext;
	}

	private boolean hasExistingComparison() {
		return lastActiveProvider != null;
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

		providers.add(provider);
		return provider;
	}

//==================================================================================================
// Service Methods
//==================================================================================================	
	@Override
	public void createComparison(Collection<Function> functions) {
		if (functions.isEmpty()) {
			return;
		}
		AnyToAnyFunctionComparisonModel model = new AnyToAnyFunctionComparisonModel(functions);
		Swing.runLater(() -> createProvider(model));
	}

	@Override
	public void createComparison(Function left, Function right) {
		AnyToAnyFunctionComparisonModel model = new AnyToAnyFunctionComparisonModel(left, right);
		Swing.runLater(() -> createProvider(model));
	}

	@Override
	public void addToComparison(Collection<Function> functions) {
		if (lastActiveProvider == null) {
			createComparison(functions);
		}
		else {
			Swing.runLater(() -> lastActiveProvider.addFunctions(functions));
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
