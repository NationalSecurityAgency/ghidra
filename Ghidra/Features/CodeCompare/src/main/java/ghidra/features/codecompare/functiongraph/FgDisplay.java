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

import java.util.*;
import java.util.function.Consumer;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.action.DockingAction;
import docking.tool.ToolConstants;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.*;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutOptions;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.FlowChartLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.services.ClipboardService;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

/**
 * This class displays a Function Graph in the left or right side of the Function Comparison view.
 */
public class FgDisplay implements OptionsChangeListener {

	private static final String FUNCTION_GRAPH_NAME = "Function Graph";

	private PluginTool tool;
	private String owner;
	private Program program;
	private FGController controller;
	private FgOptions fgOptions;
	private FormatManager userDefinedFormatManager;
	private ProgramLocation currentLocation;

	private FgDisplayProgramListener programListener = new FgDisplayProgramListener();
	private FgServiceListener serviceListener = new FgServiceListener();

	private FGColorProvider colorProvider;
	private List<FGLayoutProvider> layoutProviders;

	private Consumer<ProgramLocation> locationConsumer;
	private Consumer<FgDisplay> graphChangedConsumer;

	// Note: this class should probably be using code block highlights and not the code-level 
	// highlights already provided by the Listing.
	// FgHighlighter highlighter;

	FgDisplay(FunctionGraphCodeComparisonView fgView,
			Consumer<ProgramLocation> locationConsumer, Consumer<FgDisplay> graphChangedConsumer) {

		this.tool = fgView.getTool();
		this.owner = fgView.getOwner();
		this.locationConsumer = locationConsumer;
		this.graphChangedConsumer = graphChangedConsumer;
		fgOptions = new FgOptions();

		layoutProviders = loadLayoutProviders();
		colorProvider = new IndependentColorProvider(tool);

		init();

		FgComparisonEnv env = new FgComparisonEnv();
		FGControllerListener listener = new FgCoparisonControllerListener();
		controller = new FGController(env, listener);

		setDefaultLayout();
	}

	private void setDefaultLayout() {
		FGLayoutProvider initialLayout = layoutProviders.get(0);
		for (FGLayoutProvider layout : layoutProviders) {
			if (layout.getClass().equals(FlowChartLayoutProvider.class)) {
				initialLayout = layout;
				break;
			}
		}
		controller.changeLayout(initialLayout);
	}

	private void init() {

		tool.addServiceListener(serviceListener);

		ColorizingService colorizingService = tool.getService(ColorizingService.class);
		if (colorizingService != null) {
			colorProvider = new ToolBasedColorProvider(() -> program, colorizingService);
		}
	}

	private List<FGLayoutProvider> loadLayoutProviders() {

		// Shared Code Note: This code is mirrored in the FgDisplay for the Code Comparison API

		FGLayoutFinder layoutFinder = new DiscoverableFGLayoutFinder();
		List<FGLayoutProvider> instances = layoutFinder.findLayouts();
		if (instances.isEmpty()) {
			throw new AssertException("Could not find any layout providers. You project may not " +
				"be configured properly.");
		}

		List<FGLayoutProvider> layouts = new ArrayList<>(instances);
		Collections.sort(layouts, (o1, o2) -> -o1.getPriorityLevel() + o2.getPriorityLevel());
		return layouts;
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);
		options.removeOptionsChangeListener(this);
		options.addOptionsChangeListener(this);

		// Graph -> Function Graph
		Options subOptions = options.getOptions(FUNCTION_GRAPH_NAME);

		fgOptions.registerOptions(subOptions);
		fgOptions.loadOptions(subOptions);

		for (FGLayoutProvider layoutProvider : layoutProviders) {

			// Graph -> Function Graph -> Layout Name
			String layoutName = layoutProvider.getLayoutName();
			Options layoutToolOptions = subOptions.getOptions(layoutName);
			FGLayoutOptions layoutOptions = layoutProvider.createLayoutOptions(layoutToolOptions);
			if (layoutOptions == null) {
				continue; // many layouts do not have options
			}

			layoutOptions.registerOptions(layoutToolOptions);
			layoutOptions.loadOptions(layoutToolOptions);
			fgOptions.setLayoutOptions(layoutName, layoutOptions);
		}
	}

	public FGController getController() {
		return controller;
	}

	public String getOwner() {
		return owner;
	}

	public JComponent getComponent() {
		return controller.getViewComponent();
	}

	public void dispose() {
		if (program != null) {
			program.removeListener(programListener);
			program = null;
		}
		programListener.dispose();
		controller.cleanup();
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		// Graph -> Function Graph
		Options subOptions = options.getOptions(FUNCTION_GRAPH_NAME);
		fgOptions.loadOptions(subOptions);

		controller.optionsChanged();

		if (fgOptions.optionChangeRequiresRelayout(optionName)) {
			controller.refresh(true);
		}
		else if (VisualGraphOptions.VIEW_RESTORE_OPTIONS_KEY.equals(optionName)) {
			controller.clearViewSettings();
		}
		else {
			controller.refreshDisplayWithoutRebuilding();
		}
	}

	public void showFunction(Function function) {
		updateProgram(function);

		if (function == null) {
			controller.setStatusMessage("No Function");
			return;
		}
		if (function.isExternal()) {
			String name = function.getName(true);
			controller.setStatusMessage("\"" + name + "\" is an external function.");
			return;
		}

		Address entry = function.getEntryPoint();
		currentLocation = new ProgramLocation(program, entry);
		controller.display(program, currentLocation);
	}

	public void setLocation(ProgramLocation location) {
		controller.setLocation(location);
	}

	public ProgramLocation getLocation() {
		return controller.getLocation();
	}

	private void updateProgram(Function function) {
		Program newProgram = function == null ? null : function.getProgram();
		if (program == newProgram) {
			return;
		}
		if (program != null) {
			program.removeListener(programListener);
		}

		program = newProgram;

		if (program != null) {
			program.addListener(programListener);
			initializeOptions();
		}

	}

	public boolean isBusy() {
		return controller.isBusy();
	}

	private void refresh() {
		controller.refresh(true);
	}

	private class FgComparisonEnv implements FgEnv {

		private Navigatable navigatable = new DummyNavigatable();

		@Override
		public PluginTool getTool() {
			return tool;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public FunctionGraphOptions getOptions() {
			return fgOptions;
		}

		@Override
		public List<FGLayoutProvider> getLayoutProviders() {
			return layoutProviders;
		}

		@Override
		public void addLocalAction(DockingAction action) {
			// stub
		}

		@Override
		public FGColorProvider getColorProvider() {
			return colorProvider;
		}

		@Override
		public FormatManager getUserDefinedFormat() {
			return userDefinedFormatManager;
		}

		@Override
		public void setUserDefinedFormat(FormatManager format) {
			userDefinedFormatManager = format;
		}

		@Override
		public Navigatable getNavigatable() {
			return navigatable;
		}

		@Override
		public ProgramLocation getToolLocation() {
			// this isn't really the tool's location, but maybe this is fine for this display
			return currentLocation;
		}

		@Override
		public ProgramLocation getGraphLocation() {
			return currentLocation;
		}

		@Override
		public void setSelection(ProgramSelection selection) {
			controller.setSelection(selection);
		}
	}

	private class FgCoparisonControllerListener implements FGControllerListener {

		@Override
		public void dataChanged() {
			graphChangedConsumer.accept(FgDisplay.this);
		}

		@Override
		public void userChangedLocation(ProgramLocation location, boolean vertexChanged) {
			currentLocation = location;
			locationConsumer.accept(location);
		}

		@Override
		public void userChangedSelection(ProgramSelection selection) {
			// stub
		}

		@Override
		public void userSelectedText(String s) {
			// stub
		}

		@Override
		public void userNavigated(ProgramLocation location) {
			// stub
		}
	}

	private class DummyNavigatable implements Navigatable {

		private long id;

		DummyNavigatable() {
			id = UniversalIdGenerator.nextID().getValue();
		}

		@Override
		public long getInstanceID() {
			return id;
		}

		@Override
		public boolean goTo(Program p, ProgramLocation pl) {
			return false;
		}

		@Override
		public ProgramLocation getLocation() {
			return null;
		}

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public LocationMemento getMemento() {
			return new FgMemento(); // dummy
		}

		@Override
		public void setMemento(LocationMemento memento) {
			// stub
		}

		@Override
		public Icon getNavigatableIcon() {
			return null;
		}

		@Override
		public boolean isConnected() {
			return false;
		}

		@Override
		public boolean supportsMarkers() {
			return false;
		}

		@Override
		public void requestFocus() {
			// stub
		}

		@Override
		public boolean isVisible() {
			return true;
		}

		@Override
		public void setSelection(ProgramSelection selection) {
			// stub
		}

		@Override
		public void setHighlight(ProgramSelection highlight) {
			// stub
		}

		@Override
		public ProgramSelection getSelection() {
			return null;
		}

		@Override
		public ProgramSelection getHighlight() {
			return null;
		}

		@Override
		public String getTextSelection() {
			return null;
		}

		@Override
		public void addNavigatableListener(NavigatableRemovalListener listener) {
			// stub
		}

		@Override
		public void removeNavigatableListener(NavigatableRemovalListener listener) {
			// stub
		}

		@Override
		public boolean isDisposed() {
			return false;
		}

		@Override
		public boolean supportsHighlight() {
			return false;
		}

		@Override
		public void setHighlightProvider(ListingHighlightProvider highlightProvider,
				Program program) {
			// stub
		}

		@Override
		public void removeHighlightProvider(ListingHighlightProvider highlightProvider,
				Program p) {
			// stub
		}

	}

	private class FgMemento extends LocationMemento {
		FgMemento() {
			super((Program) null, null);
		}
	}

	private class FgDisplayProgramListener implements DomainObjectListener {

		private SwingUpdateManager updater = new SwingUpdateManager(500, 5000, () -> refresh());

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			updater.update();
		}

		public void dispose() {
			updater.dispose();
		}
	}

	private class FgServiceListener implements ServiceListener {

		@Override
		public void serviceAdded(Class<?> interfaceClass, Object service) {
			if (interfaceClass == ClipboardService.class) {
				// if we decide to support copy/paste in this viewer, then the FGClipboardProvider
				// needs to be taken out of the FGProvider and made independent.  We would also need
				// to refactor the ClipboardPlugin to not need a provider, instead adding a way to
				// get a component, context and to add/remove actions.
			}
			else if (interfaceClass == ColorizingService.class) {
				colorProvider =
					new ToolBasedColorProvider(() -> program, (ColorizingService) service);
				controller.refresh(true);
			}
		}

		@Override
		public void serviceRemoved(Class<?> interfaceClass, Object service) {
			if (interfaceClass == ColorizingService.class) {
				colorProvider = new IndependentColorProvider(tool);
				controller.refresh(true);
			}
		}
	}

	private class FgOptions extends FunctionGraphOptions {

		@Override
		public void setUseAnimation(boolean useAnimation) {
			// don't allow this to be changed; animations seem like overkill for comparisons
		}

		@Override
		public void loadOptions(Options options) {
			super.loadOptions(options);

			useAnimation = false;
		}
	}
}
