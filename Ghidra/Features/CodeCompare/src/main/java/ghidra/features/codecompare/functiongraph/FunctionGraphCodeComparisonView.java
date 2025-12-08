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
package ghidra.features.codecompare.functiongraph;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.Consumer;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.features.base.codecompare.listing.LinearAddressCorrelation;
import ghidra.features.base.codecompare.panel.CodeComparisonView;
import ghidra.features.codecompare.functiongraph.actions.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.viewer.GraphSatelliteListener;
import ghidra.program.model.correlate.HashedFunctionAddressCorrelation;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ListingAddressCorrelation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import help.Help;

/**
 * Provides a {@link CodeComparisonView} for displaying function graphs.
 * <P>
 * Known Issues:
 * 	<UL>
 * 		<LI>The options used by this API are the same as those for the Function Graph plugin.  We
 *          may find that some of the options should not apply to this API.  If true, then we would
 *          have to create a new options entry in the tool and a different options object for this 
 *          API to use.
 * 		</LI>
 * 	    <LI>Each open panel will potentially update the state that is saved in the tool.  This can
 *          lead to confusion when multiple open windows have different settings, as it is not 
 *          clear which window's settings will get saved.
 * 	    </LI>
 * 		<LI>The views do not support copying, which is consistent with the other function comparison
 *          views. 
 *      </LI>
 * 	</UL>
 */
public class FunctionGraphCodeComparisonView extends CodeComparisonView {

	public static final String NAME = "Function Graph View";

	private static final String FORMAT_KEY = "FIELD_FORMAT";
	private static final String SHOW_POPUPS_KEY = "SHOW_POPUPS";
	private static final String SHOW_SATELLITE_KEY = "SHOW_SATELLITE";

	private static final String LAYOUT_NAME = "LAYOUT_NAME";
	private static final String COMPLEX_LAYOUT_NAME = "COMPLEX_LAYOUT_NAME";
	private static final String LAYOUT_CLASS_NAME = "LAYOUT_CLASS_NAME";

	private FgDisplaySynchronizer coordinator;

	private Duo<FgDisplay> displays = new Duo<>();
	private Duo<Function> functions = new Duo<>();

	private ListingAddressCorrelation addressCorrelator;
	private boolean displaysLocked;

	private SaveState defaultSaveState;
	private SaveState saveState;
	private List<DockingAction> actions = new ArrayList<>();
	private FgTogglePopupsAction showPopupsAction;
	private FgToggleSatelliteAction showSatelliteAction;

	public FunctionGraphCodeComparisonView(String owner, PluginTool tool) {
		super(owner, tool);

		Help.getHelpService()
				.registerHelp(this, new HelpLocation(HELP_TOPIC, "FunctionGraph_Diff_View"));

		displays = buildDisplays();
		createActions();
		installSatelliteListeners();
		buildDefaultSaveState();

		buildPanel();
		setSynchronizedScrolling(true);
	}

	public String getOwner() {
		return owner;
	}

	public Duo<FgDisplay> getDisplays() {
		return displays;
	}

	/**
	 * Called by actions to signal that the user changed something worth saving.
	 */
	public void stateChanged() {
		saveShowPopups(saveState);
		saveShowSatellite(saveState);
		saveLayout(saveState);
		saveCustomFormat(saveState);

		if (!hasStateChanges()) {
			// This implies the user has made changes, but those changes match the default settings.
			// Clear the save state so no changes get written to the tool.
			saveState.clear();
		}

		tool.setConfigChanged(true);
	}

	private void buildDefaultSaveState() {
		SaveState ss = new SaveState();
		saveShowPopups(ss);
		saveLayout(ss);
		saveCustomFormat(ss);
		defaultSaveState = ss;
	}

	private void saveShowPopups(SaveState ss) {
		ss.putBoolean(SHOW_POPUPS_KEY, showPopupsAction.isSelected());
	}

	private void saveShowSatellite(SaveState ss) {
		ss.putBoolean(SHOW_SATELLITE_KEY, showSatelliteAction.isSelected());
	}

	private void loadShowPopups(SaveState ss) {
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		boolean currentShowPopups = leftController.arePopupsVisible();
		boolean savedShowPopups = ss.getBoolean(SHOW_POPUPS_KEY, currentShowPopups);
		if (currentShowPopups == savedShowPopups) {
			return;
		}

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();

		leftController.setPopupsVisible(savedShowPopups);
		rightController.setPopupsVisible(savedShowPopups);
		showPopupsAction.setSelected(savedShowPopups);
	}

	private void loadShowSatellite(SaveState ss) {
		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		boolean currentShowSatellite = leftController.isSatelliteVisible();
		boolean savedShowSatellite = ss.getBoolean(SHOW_SATELLITE_KEY, currentShowSatellite);
		if (currentShowSatellite == savedShowSatellite) {
			return;
		}

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();

		leftController.setSatelliteVisible(savedShowSatellite);
		rightController.setSatelliteVisible(savedShowSatellite);
		showSatelliteAction.setSelected(savedShowSatellite);
	}

	private void saveLayout(SaveState ss) {
		FgDisplay display = displays.get(LEFT);
		FGController controller = display.getController();
		FGLayoutProvider layout = controller.getLayoutProvider();

		SaveState layoutState = new SaveState(COMPLEX_LAYOUT_NAME);
		String layoutName = layout.getLayoutName();
		layoutState.putString(LAYOUT_NAME, layoutName);
		layoutState.putString(LAYOUT_CLASS_NAME, layout.getClass().getName());
		ss.putSaveState(COMPLEX_LAYOUT_NAME, layoutState);
	}

	private void loadLayout(SaveState ss) {

		SaveState layoutState = saveState.getSaveState(COMPLEX_LAYOUT_NAME);
		if (layoutState == null) {
			return;
		}

		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		FGLayoutProvider layout = leftController.getLayoutProvider();

		String savedLayoutName = layoutState.getString(LAYOUT_NAME, layout.getLayoutName());
		if (layout.getLayoutName().equals(savedLayoutName)) {
			return; // already set
		}

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();

		FgEnv env = leftController.getEnv();
		List<FGLayoutProvider> layoutProviders = new ArrayList<>(env.getLayoutProviders());
		for (FGLayoutProvider layoutProvider : layoutProviders) {
			String providerName = layoutProvider.getLayoutName();
			if (providerName.equals(savedLayoutName)) {
				leftController.changeLayout(layoutProvider);
				rightController.changeLayout(layoutProvider);
				break;
			}
		}
	}

	private void saveCustomFormat(SaveState ss) {
		FgDisplay display = displays.get(LEFT);
		FGController controller = display.getController();
		FormatManager format = controller.getMinimalFormatManager();
		SaveState formatState = new SaveState();
		format.saveState(formatState);
		ss.putSaveState(FORMAT_KEY, formatState);
	}

	private void loadCustomFormat(SaveState ss) {

		SaveState formatState = ss.getSaveState(FORMAT_KEY);
		if (formatState == null) {
			return;
		}

		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		FgDisplay leftDisplay = displays.get(LEFT);
		FGController leftController = leftDisplay.getController();
		FormatManager format = leftController.getMinimalFormatManager();
		SaveState testState = new SaveState();
		format.saveState(testState);

		if (equals(testState, formatState)) {
			return;
		}

		FormatManager formatManager = new FormatManager(displayOptions, fieldOptions);
		formatManager.readState(formatState);
		leftController.updateMinimalFormatManager(formatManager);

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();
		rightController.updateMinimalFormatManager(formatManager);
	}

	@Override
	public void setSaveState(SaveState ss) {
		this.saveState = ss;

		if (!hasStateChanges()) {
			return; // the given state matches the default state; nothing to do
		}

		loadShowPopups(ss);
		loadShowSatellite(ss);
		loadLayout(ss);
		loadCustomFormat(ss);
	}

	private boolean hasStateChanges() {
		if (!saveState.isEmpty()) {
			return !equals(saveState, defaultSaveState);
		}
		return false;
	}

	private boolean equals(SaveState state1, SaveState state2) {
		String s1 = state1.toString();
		String s2 = state2.toString();
		return Objects.equals(s1, s2);
	}

	private void createActions() {

		// Note: many of these actions are similar to what is in the main Function Graph.  The way
		// this class is coded, the actions do not share keybindings.  This is something we may wish 
		// to change in the future by making the key binding type sharable.

		// Both displays have the same actions they get from the Function Graph API.  We will add
		// them to the comparison provider.  We only need to add one set of actions, since they are
		// the same for both providers.
		FgDisplay left = displays.get(LEFT);
		actions.add(new FgResetGraphAction(left));

		FgDisplay right = displays.get(RIGHT);
		actions.add(new FgResetGraphAction(right));

		showPopupsAction = new FgTogglePopupsAction(this);
		FGController controller = left.getController();
		boolean showPopups = controller.arePopupsVisible();
		showPopupsAction.setSelected(showPopups);

		showSatelliteAction = new FgToggleSatelliteAction(this);
		boolean showSatellite = controller.isSatelliteVisible();
		showSatelliteAction.setSelected(showSatellite);

		actions.add(showSatelliteAction);
		actions.add(showPopupsAction);
		actions.add(new FgRelayoutAction(this));
		actions.add(new FgChooseFormatAction(this));
	}

	private void installSatelliteListeners() {

		FgDisplay left = displays.get(LEFT);
		FgDisplay right = displays.get(RIGHT);
		FGController leftController = left.getController();
		FGController rightController = right.getController();

		GraphSatelliteListener listener = new GraphSatelliteListener() {

			@Override
			public void satelliteVisibilityChanged(boolean docked, boolean visible) {
				if (visible) {
					leftController.setSatelliteVisible(true);
					rightController.setSatelliteVisible(true);
				}
				showSatelliteAction.setSelected(visible);
				stateChanged();
			}
		};

		FGView lv = leftController.getView();
		FGView rv = rightController.getView();
		lv.addSatelliteListener(listener);
		rv.addSatelliteListener(listener);
	}

	@Override
	public List<DockingAction> getActions() {
		List<DockingAction> superActions = super.getActions();
		superActions.addAll(0, actions);
		return actions;
	}

	@Override
	protected void comparisonDataChanged() {

		maybeLoadFunction(LEFT, comparisonData.get(LEFT).getFunction());
		maybeLoadFunction(RIGHT, comparisonData.get(RIGHT).getFunction());

		addressCorrelator = createCorrelator();
		// updateProgramViews();
		updateCoordinator();
		//initializeCursorMarkers();
		updateActionEnablement();
		validate();
	}

	private ListingAddressCorrelation createCorrelator() {
		Function f1 = getFunction(LEFT);
		Function f2 = getFunction(RIGHT);
		if (f1 != null && f2 != null) {
			try {
				return new HashedFunctionAddressCorrelation(f1, f2, TaskMonitor.DUMMY);
			}
			catch (CancelledException | MemoryAccessException e) {
				// fall back to linear address correlation
			}
		}
		if (comparisonData.get(LEFT).isEmpty() || comparisonData.get(RIGHT).isEmpty()) {
			return null;
		}
		return new LinearAddressCorrelation(comparisonData);
	}

	private void updateCoordinator() {
		if (coordinator != null) {
			coordinator.dispose();
			coordinator = null;
		}
		if (displaysLocked) {
			coordinator = new FgDisplaySynchronizer(displays, addressCorrelator);
			coordinator.sync(activeSide);
		}
	}

	private void maybeLoadFunction(Side side, Function function) {
		// we keep a local copy of the function so we know if it is already decompiled
		if (functions.get(side) == function) {
			return;
		}

		// Clear the scroll info and highlight info to prevent unnecessary highlighting, etc.
		loadFunction(side, null);
		loadFunction(side, function);

	}

	private void loadFunction(Side side, Function function) {
		if (functions.get(side) != function) {
			functions = functions.with(side, function);
			displays.get(side).showFunction(function);
		}
	}

	private Duo<FgDisplay> buildDisplays() {

		// The function graph's display is not ready until a graph is loaded.  It also gets rebuilt
		// each time the graph is reloaded.  To correctly install listeners, we need to update them
		// as the graph is rebuilt.
		Consumer<FgDisplay> graphChangedCallback = display -> {
			Side side = getSide(display);
			addMouseAndFocusListeners(side);
		};

		FgDisplay leftDisplay =
			new FgDisplay(this, l -> locationChanged(LEFT, l), graphChangedCallback);
		FgDisplay rightDisplay =
			new FgDisplay(this, l -> locationChanged(RIGHT, l), graphChangedCallback);

		return new Duo<>(leftDisplay, rightDisplay);
	}

	private Side getSide(FgDisplay display) {
		FgDisplay leftDisplay = displays.get(LEFT);
		if (display == leftDisplay) {
			return LEFT;
		}
		return RIGHT;
	}

	private void locationChanged(Side side, ProgramLocation location) {
		if (coordinator != null) {
			coordinator.setLocation(side, location);
		}
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void dispose() {
		setSynchronizedScrolling(false); // disposes any exiting coordinator
		displays.each(FgDisplay::dispose);
	}

	/**
	 * Gets the display from the active side.
	 * @return the active display
	 */
	public FgDisplay getActiveDisplay() {
		return displays.get(activeSide);
	}

	@Override
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {
		FgDisplay display = getActiveDisplay();
		Component component = event != null ? event.getComponent()
				: display.getComponent();
		boolean isLeft = activeSide == LEFT;
		return new FgComparisonContext(provider, this, display, component, isLeft);
	}

	@Override
	public void updateActionEnablement() {
		// stub
	}

	@Override
	public void setSynchronizedScrolling(boolean synchronize) {
		if (coordinator != null) {
			coordinator.dispose();
			coordinator = null;
		}

		displaysLocked = synchronize;
		if (displaysLocked) {
			coordinator = new FgDisplaySynchronizer(displays, addressCorrelator);
			coordinator.sync(activeSide);
		}
	}

	@Override
	public JComponent getComparisonComponent(Side side) {
		return displays.get(side).getComponent();
	}

	public boolean isBusy() {
		return displays.get(LEFT).isBusy() || displays.get(RIGHT).isBusy();
	}
}
