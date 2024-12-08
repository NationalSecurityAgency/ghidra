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
package ghidra.machinelearning.functionfinding;

import java.util.*;

import org.tribuo.classification.Label;

import aQute.bnd.unmodifiable.Lists;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.RestrictedAddressSetContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Function Finder",
	description = "Trains a random forest model to find function starts.",
	servicesRequired = { GoToService.class, ProgramManager.class},
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramClosedPluginEvent.class}
	)
//@formatter:on

/**
 * A {@link ProgramPlugin} for training a model on the starts of known functions in a
 * program and then using that model to look for more functions (in the source program or
 * another program selected by the user).
 */
public class RandomForestFunctionFinderPlugin extends ProgramPlugin
		implements OptionsChangeListener {

	public static final Label FUNC_START = new Label("S");
	public static final Label NON_START = new Label("N");
	private static final String ACTION_NAME = "Search for Code and Functions";
	private static final String MENU_PATH_ENTRY = "For Code and Functions...";
	private static final String TEST_SET_MAX_SIZE_OPTION_NAME = "Maximum size of test sets";
	static final Long TEST_SET_MAX_SIZE_DEFAULT = 1000000l;
	private Long testSetMax;
	private static final String MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME =
		"Minimum Length of Undefined Range to Search";
	static final Long MIN_UNDEFINED_RANGE_SIZE_DEFAULT = 16l;
	private Long minUndefinedRangeSize;

	private FunctionStartRFParamsDialog paramsDialog;

	//this map is used to close all providers associated with a program p
	//when p is closed
	private Map<Program, List<ProgramAssociatedComponentProviderAdapter>> programsToProviders;

	/**
	 * Creates the plugin for the given tool.
	 * @param tool tool for plugin
	 */
	public RandomForestFunctionFinderPlugin(PluginTool tool) {
		super(tool);
		programsToProviders = new HashMap<>();
	}

	@Override
	public void init() {
		createActions();
		initOptions(getTool().getOptions("Random Forest Function Finder"));
	}

	@Override
	protected void dispose() {
		super.dispose();

		if (paramsDialog != null) {
			paramsDialog.dispose();
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		switch (optionName) {
			case TEST_SET_MAX_SIZE_OPTION_NAME:
				Long newMax = (Long) newValue;
				if (newMax <= 0) {
					//does this actually inform the user of the problem?
					throw new OptionsVetoException(
						TEST_SET_MAX_SIZE_OPTION_NAME + " must be positive!");
				}
				testSetMax = newMax;
				break;
			case MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME:
				Long newMin = (Long) newValue;
				if (newMin <= 0) {
					throw new OptionsVetoException(
						MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME + " must be positive!");
				}
				minUndefinedRangeSize = newMin;
				break;
			default:
				Msg.showError(this, null, "Unknown option", "Unknown option: " + optionName);
		}
	}

	/**
	 * Record the existence of a {@link ProgramAssociatedComponentProviderAdapter} so that it can
	 * be closed if its associated program is closed
	 * @param provider provider
	 */
	void addProvider(ProgramAssociatedComponentProviderAdapter provider) {
		List<ProgramAssociatedComponentProviderAdapter> providers =
			programsToProviders.computeIfAbsent(provider.getProgram(), p -> new ArrayList<>());
		providers.add(provider);
		tool.addComponentProvider(provider, true);
	}

	/**
	 * Remove the provider from the list of tracked providers
	 * @param provider provider
	 */
	void removeProvider(ProgramAssociatedComponentProviderAdapter provider) {
		programsToProviders.get(provider.getProgram()).remove(provider);
	}

	/**
	 * Sets the current selection.  Cf. {@link FunctionStartRFParamsDialog#addGeneralActions}
	 * @param selection new selection
	 */
	void setSelection(ProgramSelection selection) {
		currentSelection = selection;
	}

	/**
	 * Returns the maximum size of a test set.  Users can set this value via a plugin option.
	 * @return max size
	 */
	Long getTestMaxSize() {
		return testSetMax;
	}

	/**
	 * Returns the minimum size of an undefined range to search for function starts.  Users
	 * can set this value via a plugion option.
	 * @return min undefined range size
	 */
	Long getMinUndefinedRangeSize() {
		return minUndefinedRangeSize;
	}

	/**
	 * Null out the dialog
	 */
	void resetDialog() {
		paramsDialog = null;
	}

	@Override
	protected void programClosed(Program p) {
		//ProgramAssociatedComponentProviderAdapter.closeComponent modifies values of
		//programsToProviders, so make a copy to avoid a ConcurrentModificationException
		List<ProgramAssociatedComponentProviderAdapter> providersToClose =
			Lists.copyOf(programsToProviders.getOrDefault(p, Collections.emptyList()));
		for (ProgramAssociatedComponentProviderAdapter provider : providersToClose) {
			provider.closeComponent();
		}
		programsToProviders.remove(p);
		if (paramsDialog == null) {
			return;
		}
		if (!paramsDialog.getTrainingSource().equals(p)) {
			return;
		}
		paramsDialog.dismissCallback();
	}

	private void createActions() {

		new ActionBuilder(ACTION_NAME, getName())
			.menuPath(ToolConstants.MENU_SEARCH, MENU_PATH_ENTRY)
			.menuGroup("search for", null)
			.description("Train models to search for function starts")
			.helpLocation(new HelpLocation(getName(), getName()))
			.withContext(NavigatableActionContext.class, true)
			.validContextWhen(c -> !(c instanceof RestrictedAddressSetContext))
			.onAction(c -> {
				displayDialog(c);
			})
			.buildAndInstall(tool);
	}

	private void displayDialog(NavigatableActionContext c) {
		if (paramsDialog == null) {
			paramsDialog = new FunctionStartRFParamsDialog(this);
		}
		tool.showDialog(paramsDialog, c.getComponentProvider());
	}

	private void initOptions(ToolOptions options) {
		options.registerOption(TEST_SET_MAX_SIZE_OPTION_NAME, TEST_SET_MAX_SIZE_DEFAULT,
			new HelpLocation(getName(), "MaxTestSetSize"),
			"Maximum sizes for test sets (must be positive).");
		testSetMax = options.getLong(TEST_SET_MAX_SIZE_OPTION_NAME, TEST_SET_MAX_SIZE_DEFAULT);
		options.registerOption(MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME,
			MIN_UNDEFINED_RANGE_SIZE_DEFAULT,
			new HelpLocation(getName(), "MinLengthUndefinedRange"),
			"Minimum Size of an Undefined AddressRange to search (must be positive).");
		minUndefinedRangeSize =
			options.getLong(MIN_UNDEFINED_RANGE_SIZE_OPTION_NAME, MIN_UNDEFINED_RANGE_SIZE_DEFAULT);
		options.addOptionsChangeListener(this);
	}
}
