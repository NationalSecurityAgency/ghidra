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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;

import javax.swing.JComponent;

import com.google.common.cache.*;

import docking.options.OptionsService;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.ListingMiddleMouseHighlightProvider;
import ghidra.app.plugin.core.functiongraph.FGColorProvider;
import ghidra.app.plugin.core.functiongraph.SetFormatDialogComponentProvider;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.marker.MarginProviderSupplier;
import ghidra.app.services.ButtonPressedListener;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.viewer.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

public class FGController implements ProgramLocationListener, ProgramSelectionListener {

	private FgEnv env;
	private FGModel model;
	private FGView view;

	private FGData functionGraphData = new EmptyFunctionGraphData("Uninitialized Function Graph");
	private FunctionGraphViewSettings viewSettings = new NoFunctionGraphViewSettings();
	private FGVertex lastUserNavigatedVertex;

	/** Field format manager when looking at a vertex in full screen mode (same as code viewer */
	private FormatManager fullFormatManager;

	/** Field format manager when looking at a vertex in graph mode */
	private FormatManager minimalFormatManager;

	/** Field format manager for restoring to the default 'minimal' view */
	private FormatManager defaultFormatManager; // lazy!

	private FunctionGraphOptions functionGraphOptions;
	private FGControllerListener listener;

	private FgHighlightProvider sharedHighlightProvider;
	private StringSelectionListener sharedStringSelectionListener =
		string -> listener.userSelectedText(string);

	private Cache<Function, FGData> cache;
	private BiConsumer<FGData, Boolean> fgDataDisposeListener = (data, evicted) -> {
		// dummy
	};

	private WeakSet<MarginProviderSupplier> marginProviders =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public FGController(FgEnv env, FGControllerListener controllerListener) {
		this.env = env;
		this.listener = Objects.requireNonNull(controllerListener);
		this.cache = buildCache(this::cacheValueRemoved);
		this.model = new FGModel(this);
		this.view = new FGView(this, model.getTaskMonitorComponent());

		this.functionGraphOptions = env.getOptions();
	}

	public FgEnv getEnv() {
		return env;
	}

	private boolean disposeGraphDataIfNotInUse(FGData data) {

		// Be careful not to dispose current graph data.  This method gets called whenever
		// data is removed from the cache.  But there are several cases where data is removed
		// from the cache while it is still currently in view.  (Typically this occurs if we are replacing
		// the current function's graph with a new graph for that function.) Normally, we want to dispose
		// any data that is removed from the cache, but we can't if it is still in use.  Later,
		// when the current data is replace with new data, it will be disposed.

		if (data == functionGraphData) {
			return false; // don't dispose currently used data
		}

		data.dispose();
		fgDataDisposeListener.accept(data, true);
		return true;
	}

	private FormatManager createMinimalFormatManager() {
		FormatManager userDefinedFormat = env.getUserDefinedFormat();
		if (userDefinedFormat != null) {
			return userDefinedFormat;
		}
		return createDefaultFormat();
	}

	private FormatManager createFullFormatManager() {
		CodeViewerService codeViewer =
			env.getTool().getService(CodeViewerService.class);

		if (codeViewer != null) {
			// Prefer the manager from the service, as this is the current state of the Listing.
			return codeViewer.getFormatManager();
		}

		// No code viewer service implies we are not in the default tool
		PluginTool tool = env.getTool();
		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		return new FormatManager(displayOptions, fieldOptions);

	}

	public FormatManager getMinimalFormatManager() {
		if (minimalFormatManager == null) {
			setMinimalFormatManager(createMinimalFormatManager());
		}
		return minimalFormatManager;
	}

	private void setMinimalFormatManager(FormatManager formatManager) {
		this.minimalFormatManager = formatManager;
		FgHighlightProvider highlightProvider = lazilyCreateSharedHighlightProvider();
		minimalFormatManager.addHighlightProvider(highlightProvider);
	}

	public void updateMinimalFormatManager(FormatManager newFormatManager) {

		// ensure the format manager has been created
		getMinimalFormatManager();

		SaveState saveState = new SaveState();
		newFormatManager.saveState(saveState);
		minimalFormatManager.readState(saveState);
		env.setUserDefinedFormat(minimalFormatManager);
		view.repaint();
	}

	public FormatManager getFullFormatManager() {
		if (fullFormatManager == null) {
			fullFormatManager = createFullFormatManager();
		}
		return fullFormatManager;
	}

	public FormatManager getDefaultFormatManager() {
		if (defaultFormatManager == null) {
			defaultFormatManager = createDefaultFormat();
		}
		return defaultFormatManager;
	}

	private FgHighlightProvider lazilyCreateSharedHighlightProvider() {
		if (sharedHighlightProvider != null) {
			return sharedHighlightProvider;
		}

		JComponent centerOverComponent = view.getPrimaryGraphViewer();
		sharedHighlightProvider =
			new FgHighlightProvider(env.getTool(), centerOverComponent);
		return sharedHighlightProvider;
	}

	public void formatChanged() {
		setMinimalFormatManager(env.getUserDefinedFormat());
		view.repaint();
	}

	public Navigatable getNavigatable() {
		return env.getNavigatable();
	}

	private FormatManager createDefaultFormat() {
		OptionsService options = env.getTool().getService(OptionsService.class);
		ToolOptions displayOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		// Now set up
		FormatManager newMinimizedFormatManager = new FormatManager(displayOptions, fieldOptions);
		for (int i = 0; i < newMinimizedFormatManager.getNumModels(); i++) {
			FieldFormatModel formatModel = newMinimizedFormatManager.getModel(i);
			int numRows = formatModel.getNumRows();
			for (int row = 0; row < numRows; row++) {
				FieldFactory[] allRowFactories = formatModel.getFactorys(row);
				for (int col = allRowFactories.length - 1; col >= 0; col--) {
					FieldFactory fieldFactory = allRowFactories[col];

					if (fieldFactory.getFieldName().equals("Operands")) {
						fieldFactory.setWidth(195);
						formatModel.updateRow(row);
					}
					else if (fieldFactory.getFieldName().equals("Label")) {
						fieldFactory.setWidth(150);
						formatModel.updateRow(row);
					}
					else if (fieldFactory.getFieldName().equals("Address")) {
						fieldFactory.setWidth(50);
						formatModel.updateRow(row);
					}
					else if (fieldFactory.getFieldName().equals("Mnemonic")) {
						fieldFactory.setWidth(37);
						formatModel.updateRow(row);
					}
					else if (isSpacerBeforeLabel(fieldFactory, allRowFactories, col)) {
						// Magic number based upon default sizes in the FormatManager.  This
						// value is the width of the Address and Mnemonic fields, minus some
						// space so that the Label field will start before the Operands field
						fieldFactory.setWidth(75);
						formatModel.updateRow(row);
					}
					// function header stuff
					else if (fieldFactory.getFieldName().equals("Function Signature") ||
						fieldFactory.getFieldName().equals("Variable Type") ||
						fieldFactory.getFieldName().equals("Variable Location") ||
						fieldFactory.getFieldName().equals("Variable Name")) {
						// we need this block so that the default case below doesn't delete
					}
					else if (isSpacerBeforeVariables(fieldFactory, allRowFactories, col)) {
						// keep for aesthetics; make about the size of address
						fieldFactory.setWidth(50);
						formatModel.updateRow(row);
					}
					// remove any other fields
					else if (!fieldFactory.getFieldName().equals("Address") &&
						!fieldFactory.getFieldName().equals("Mnemonic")) {
						formatModel.removeFactory(row, col);
					}
				}
			}
		}

		for (int i = 0; i < newMinimizedFormatManager.getNumModels(); i++) {
			FieldFormatModel codeUnitFormat = newMinimizedFormatManager.getModel(i);
			int numRows = codeUnitFormat.getNumRows();
			for (int j = numRows - 1; j >= 0; j--) {
				FieldFactory[] allRowFactories = codeUnitFormat.getFactorys(j);
				if (allRowFactories.length == 0) {
					codeUnitFormat.removeRow(j);
				}
			}
		}

		return newMinimizedFormatManager;
	}

	private boolean isSpacerBeforeLabel(FieldFactory fieldFactory, FieldFactory[] allRowFactories,
			int column) {

		if (!fieldFactory.getFieldName().equals("Spacer")) {
			return false;
		}

		// We want to keep the spacer that precedes the label field.  This spacer is expected
		// to be the first spacer in its row
		if (column != 0) {
			return false;
		}

		if (allRowFactories.length < 2) {
			return false;
		}

		FieldFactory previousFactory = allRowFactories[1];
		return previousFactory.getFieldName().equals("Label");
	}

	private boolean isSpacerBeforeVariables(FieldFactory fieldFactory,
			FieldFactory[] allRowFactories, int column) {

		if (!fieldFactory.getFieldName().equals("Spacer")) {
			return false;
		}

		// We want to keep the spacer that precedes the label field.  This spacer is expected
		// to be the first spacer in its row
		if (column != 0) {
			return false;
		}

		if (allRowFactories.length < 2) {
			return false;
		}

		FieldFactory previousFactory = allRowFactories[1];
		return previousFactory.getFieldName().equals("Variable Type");
	}

	/**
	 * Sets the message that will appear in the lower part of the graph.
	 *
	 * @param message the message to display
	 */
	public void setStatusMessage(String message) {
		view.setStatusMessage(message);
	}

//==================================================================================================
// Interface methods
//==================================================================================================

	// this is a callback from the vertex's listing panel
	@Override
	public void programLocationChanged(ProgramLocation location, EventTrigger trigger) {
		if (trigger == EventTrigger.GUI_ACTION) {
			handleLocationChangedFromVertex(location);
		}
	}

	private void handleLocationChangedFromVertex(ProgramLocation loc) {
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		FGVertex newFocusedVertex = graph.getFocusedVertex();
		boolean vertexChanged = lastUserNavigatedVertex != newFocusedVertex;
		lastUserNavigatedVertex = newFocusedVertex;

		viewSettings.setLocation(loc);
		listener.userChangedLocation(loc, vertexChanged);
	}

	// this is a callback from the vertex's listing panel
	@Override
	public void programSelectionChanged(ProgramSelection selection, EventTrigger trigger) {
		if (trigger != EventTrigger.GUI_ACTION) {
			return;
		}
		// We need to translate the given selection (which is from a single vertex) to the current
		// overall selection for the graph (which includes the selection from all vertices).  We
		// do this so that a selection change in one vertex does not clear the selection in
		// other vertices
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		ProgramSelection fullSelection = graph.getProgramSelectionForAllVertices();

		// push the user changes up to the provider
		viewSettings.setSelection(fullSelection);
		listener.userChangedSelection(fullSelection);
	}

//==================================================================================================
// Grouping Methods (to be moved in a later refactoring)
//==================================================================================================

	public void groupSelectedVertices() {
		groupSelectedVertices(null);
	}

	public void groupSelectedVertices(Point2D location) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.groupSelectedVertices(this, location);
	}

	public void ungroupAllVertices() {
		FGViewUpdater updater = view.getViewUpdater();
		updater.ungroupAllVertices(this);
	}

	public void addToGroup(GroupedFunctionGraphVertex group, Set<FGVertex> vertices) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.addToGroup(this, group, vertices);
	}

	public void ungroupVertex(GroupedFunctionGraphVertex group) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.ungroupVertex(this, group);
	}

	public void splitVertex(FGVertex v, Address address) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.splitVertex(this, v, address);
	}

	public void mergeVertexWithParent(FGVertex v) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.mergeVertexWithParent(this, v);
	}

	public String promptUserForGroupVertexText(JComponent parent, String userText,
			Set<FGVertex> vertices) {
		FGViewUpdater updater = view.getViewUpdater();
		return updater.promptUserForGroupVertexText(parent, userText, vertices);
	}

	public String generateGroupVertexDescription(Set<FGVertex> vertices) {
		return GroupedFunctionGraphVertex.generateGroupVertexDescription(vertices);
	}

	public void regroupVertices(FGVertex v) {
		FGViewUpdater updater = view.getViewUpdater();
		updater.regroupVertices(this, v);
	}

	public boolean installGroupVertex(GroupedFunctionGraphVertex vertex, Point2D location) {
		FGViewUpdater updater = view.getViewUpdater();
		return updater.installGroupVertex(this, vertex, location);
	}

//==================================================================================================
// End Group Methods
//==================================================================================================

//==================================================================================================
//  Methods called by the providers
//==================================================================================================

	public void programClosed(Program program) {
		clearCacheForProgram(program);
	}

	private void clearCacheForProgram(Program program) {
		for (Function function : cache.asMap().keySet()) {
			Program functionProgram = function.getProgram();
			if (functionProgram == program) {
				cache.invalidate(function);
			}
		}
	}

	private void disposeCache() {
		cache.invalidateAll();
	}

	public boolean isSatelliteVisible() {
		return view.isSatelliteVisible();
	}

	public void setSatelliteVisible(boolean visible) {
		view.setSatelliteVisible(visible);
	}

	public boolean isSatelliteDocked() {
		return view.isSatelliteDocked();
	}

	public void primaryProviderHidden() {
		clear();
	}

	public void setPopupsVisible(boolean visible) {
		view.setPopupsVisible(visible);
	}

	public boolean arePopupsVisible() {
		return view.arePopupsVisible();
	}

	public boolean arePopupsEnabled() {
		return arePopupsVisible();
	}

	public FGVertex getFocusedVertex() {
		if (!hasResults()) {
			return null;
		}

		return view.getFocusedVertex();
	}

	public FGVertex getEntryPointVertex() {
		if (!hasResults()) {
			return null;
		}
		return view.getEntryPointVertex();
	}

	public Set<FGVertex> getSelectedVertices() {
		if (!hasResults()) {
			return null;
		}
		return view.getSelectedVertices();
	}

	public boolean hasResults() {
		return functionGraphData.hasResults();
	}

	public void cleanup() {
		clear();
		disposeCache();
		model.cleanup();
		view.cleanup();
	}

	public ProgramSelection getSelection() {
		return viewSettings.getSelection();
	}

	public void setSelection(ProgramSelection selection) {
		viewSettings.setSelection(selection);
	}

	public void setHighlight(ProgramSelection highlight) {
		viewSettings.setHighlight(highlight);
	}

	public void setGraphPerspective(GraphPerspectiveInfo<FGVertex, FGEdge> info) {
		viewSettings.setFunctionGraphPerspectiveInfo(info);
	}

	public FGModel getModel() {
		return model;
	}

	public FGView getView() {
		return view;
	}

	public void clear() {
		model.cancelAll();
		viewSettings = new NoFunctionGraphViewSettings();

		if (functionGraphData == null || functionGraphData.hasResults()) {
			doSetFunctionGraphData(new EmptyFunctionGraphData("No Function"));
		}
	}

	public void clearViewSettings() {
		GraphPerspectiveInfo<FGVertex, FGEdge> info =
			GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();
		setGraphPerspective(info);
	}

	public void display(Program program, ProgramLocation location) {
		if (viewContainsLocation(location)) {
			// no need to rebuild the graph; just set the location
			viewSettings.setLocation(location);
			return;
		}

		if (loadCachedGraphData(program, location)) {
			// no need to rebuild the graph; just set the location
			viewSettings.setLocation(location);
			return;
		}

		doDisplay(program, location, null /* don't keep current perspective*/);
	}

	private boolean viewContainsLocation(ProgramLocation location) {
		return !model.isBusy() && view.containsLocation(location);
	}

	private boolean loadCachedGraphData(Program program, ProgramLocation location) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(location.getAddress());

		if (function == null) { // cache can't handle null keys
			return false;
		}
		FGData cachedFunctionGraphData = cache.getIfPresent(function);
		if (cachedFunctionGraphData == null) {
			return false;
		}

		// cancel any pending graph tasks, so that previous requests don't overwrite the latest request
		model.cancelAll();
		doSetFunctionGraphData(cachedFunctionGraphData);
		return true;
	}

	private void clearCacheForLocation(Program program, ProgramLocation location) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(location.getAddress());
		if (function != null) {
			cache.invalidate(function);
		}
	}

	private void clearCacheForAddress(Program program, Address address) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(address);
		if (function != null) {
			cache.invalidate(function);
		}
	}

	/**
	 * Tells this provider to refresh, which means to rebuild the graph and relayout the
	 * vertices.
	 * @param keepPerspective true to keep the perspective (e.g., zoom level and view position)
	 */
	public void refresh(boolean keepPerspective) {

		if (functionGraphData.hasResults()) {
			//
			// We use the graph's data over the 'currentXXX' data, as there is a chance that the
			// latter values have been set to new values, while the graph has differing data.  In
			// that case we have made the decision to prefer the graph's data.
			//
			Function function = functionGraphData.getFunction();
			Address address = function.getEntryPoint();
			ProgramLocation currentLocation = env.getGraphLocation();
			Address currentAddress = currentLocation.getAddress();
			if (function.getBody().contains(currentAddress)) {
				// prefer the current address if it is within the current function (i.e., the
				// location hasn't changed out from under the graph due to threading issues)
				address = currentAddress;
			}

			Program program = function.getProgram();
			ProgramLocation programLocation = new ProgramLocation(program, address);
			rebuildDisplay(program, programLocation, keepPerspective);
			return;
		}

		Program program = env.getProgram();
		ProgramLocation currentLocation = env.getGraphLocation();
		rebuildDisplay(program, currentLocation, keepPerspective);
	}

	/*
	 * This method differs from the <tt>refresh</tt>...() methods in that it will trigger a
	 * graph rebuild, clearing any cached graph data in the process.  If <tt>maintainPerspective</tt>
	 * is true, then view settings will be maintained (i.e., the zoom level and location).
	 */
	public void rebuildDisplay(Program program, ProgramLocation programLocation,
			boolean maintainPerspective) {
		if (program == null || programLocation == null) {
			clear();
			return;
		}

		clearCacheForLocation(program, programLocation);
		model.reset();

		// record the view settings before performing the re-display
		GraphPerspectiveInfo<FGVertex, FGEdge> perspective = null;
		if (maintainPerspective) {
			perspective = getGraphPerspective(programLocation);
		}
		doDisplay(program, programLocation, perspective);
	}

	public void rebuildCurrentDisplay() {
		refresh(true);
	}

	public void resetGraph() {
		if (!functionGraphData.hasResults()) {
			// should not happen
			return;
		}

		// remove all saved locations and group info
		view.clearUserLayoutSettings();

		Function function = functionGraphData.getFunction();
		ProgramLocation location =
			new ProgramLocation(function.getProgram(), function.getEntryPoint());
		rebuildDisplay(function.getProgram(), location, false);

		// we are changing the location above--make sure the external tool knows of it
		ProgramLocation externalLocation = env.getToolLocation();
		if (!externalLocation.getAddress().equals(location.getAddress())) {
			listener.userChangedLocation(location, false);
		}
	}

	private void doDisplay(Program program, ProgramLocation location,
			GraphPerspectiveInfo<FGVertex, FGEdge> perspective) {
		model.graphFunction(program, location);

		view.setStatusMessage("Graphing function for address: " + location.getAddress());
		viewSettings = new PendingFunctionGraphViewSettings(viewSettings, perspective);
		viewSettings.setLocation(location);
	}

	public void optionsChanged() {
		view.optionsChanged();
	}

	public void refreshDisplayWithoutRebuilding() {
		if (functionGraphData.hasResults()) {
			view.refreshDisplayWithoutRebuilding();
		}
	}

	public void refreshDisplayForAddress(Address address) {
		view.refreshDisplayForAddress(address);
	}

	public Program getProgram() {
		return env.getProgram();
	}

	public FGData getFunctionGraphData() {
		return functionGraphData;
	}

	public Function getGraphedFunction() {
		if (functionGraphData != null && !model.isBusy()) {
			return functionGraphData.getFunction();
		}
		return null;
	}

	public boolean isBusy() {
		return model.isBusy();
	}

	public JComponent getViewComponent() {
		return view.getViewComponent();
	}

	public void changeLayout(FGLayoutProvider newLayout) {
		FGLayoutProvider previousLayout = (FGLayoutProvider) view.getLayoutProvider();
		view.setLayoutProvider(newLayout);

		if (previousLayout == null) {
			refresh(false);
			return;
		}

		String previousLayoutName = previousLayout.getLayoutName();
		String newLayoutName = newLayout.getLayoutName();
		if (previousLayoutName.equals(newLayoutName)) {
			view.relayout();
		}
		else {
			refresh(false);
		}
	}

	public FGLayoutProvider getLayoutProvider() {
		return (FGLayoutProvider) view.getLayoutProvider();
	}

	public void showFormatChooser() {
		FGVertex vertex = view.getFocusedVertex();
		if (vertex == null) {
			vertex = view.getEntryPointVertex();
		}

		PluginTool tool = env.getTool();
		SetFormatDialogComponentProvider setFormatDialog =
			new SetFormatDialogComponentProvider(getDefaultFormatManager(), minimalFormatManager,
				tool, env.getProgram(), vertex.getAddresses());
		tool.showDialog(setFormatDialog);
		FormatManager newFormatManager = setFormatDialog.getNewFormatManager();
		if (newFormatManager == null) {
			return;
		}

		updateMinimalFormatManager(newFormatManager);
	}

	public void showXRefsDialog() {
		PluginTool tool = env.getTool();
		Program program = env.getProgram();
		List<Reference> references = getXReferencesToGraph();
		XRefChooserDialog chooserDialog = new XRefChooserDialog(references, program, tool);

		JComponent centerOverComponent = view.getPrimaryGraphViewer();
		tool.showDialog(chooserDialog, centerOverComponent);
		Reference reference = chooserDialog.getSelectedReference();
		if (reference == null) {
			return; // the user cancelled
		}

		listener.userNavigated(new ProgramLocation(program, reference.getFromAddress()));
	}

	private List<Reference> getXReferencesToGraph() {
		Program program = env.getProgram();
		Function function = getGraphedFunction();

		ReferenceManager referenceManager = program.getReferenceManager();
		Address entryPoint = function.getEntryPoint();

		List<Reference> references = new ArrayList<>();
		ReferenceIterator referencesIterator = referenceManager.getReferencesTo(entryPoint);
		while (referencesIterator.hasNext()) {
			Reference reference = referencesIterator.next();
			references.add(reference);
		}
		return references;
	}

	public void setVertexHoverPathHighlightMode(PathHighlightMode edgeHoverMode) {
		view.setVertexHoverPathHighlightMode(edgeHoverMode);
	}

	public void setVertexFocusPathHighlightMode(PathHighlightMode edgeFocusMode) {
		view.setVertexFocusPathHighlightMode(edgeFocusMode);
	}

	public PathHighlightMode getVertexHoverPathHighlightMode() {
		return view.getVertexHoverPathHighlightMode();
	}

	public PathHighlightMode getVertexFocusPathHighlightMode() {
		return view.getVertexFocusPathHighlightMode();
	}

	public GraphPerspectiveInfo<FGVertex, FGEdge> getGraphPerspective(ProgramLocation location) {
		if (model.isBusy() || !hasResults()) {
			return GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();
		}

		if (location == null) {
			return GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();

		// get the vertex for the program location
		FGVertex vertex = graph.getVertexForAddress(location.getAddress());

		if (vertex == null) {
			// this can happen when the location we are given is not in our graph
			return GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();
		}

		return view.generateGraphPerspective();
	}

	public boolean isScaledPastInteractionThreshold() {
		return view.isScaledPastInteractionThreshold();
	}

	/**
	 * Signals that something major has changed for the program and we don't know where, so clear
	 * all cached functions for the given program.
	 *
	 * BLEH!: I don't like clearing the cache this way...another options is to mark all cached
	 * values as stale, somehow. If we did this, then when the view reuses the cached data, it could
	 * signal to the user that the graph is out-of-date.
	 *
	 * @param program the program
	 */
	public void invalidateAllCacheForProgram(Program program) {
		clearCacheForProgram(program);
		view.setGraphViewStale(true);
	}

	public void invalidateCacheForAddresses(AddressSet addresses) {
		Function currentFunction = functionGraphData.getFunction();
		if (currentFunction == null) {
			return;
		}

		AddressSetView body = currentFunction.getBody();
		if (addresses.intersects(body)) {
			// the current function has been affected by changes at the given
			// addresses--mark the view as stale
			view.setGraphViewStale(true);
		}

		// now clear any graph cache for the given affected addresses
		Program program = currentFunction.getProgram();
		AddressIterator iterator = addresses.getAddresses(true);
		while (iterator.hasNext()) {
			Address address = iterator.next();
			clearCacheForAddress(program, address);
		}
	}

	public void addMarkerProviderSupplier(MarginProviderSupplier supplier) {
		marginProviders.add(supplier);
	}

	public void removeMarkerProviderSupplier(MarginProviderSupplier supplier) {
		marginProviders.add(supplier);
	}

//==================================================================================================
//  Methods called by the model
//==================================================================================================

	public void setFunctionGraphData(FGData data) {
		if (!data.hasResults()) {
			if (reuseCurrentGraph(data)) {
				// leave previous valid function graph visible when the new graph is invalid
				return;
			}
		}
		else {
			cache.put(data.getFunction(), data);
		}

		doSetFunctionGraphData(data);
	}

	private boolean reuseCurrentGraph(FGData data) {
		if (functionGraphData == null || !functionGraphData.hasResults()) {
			return false;
		}

		view.setStatusMessage(data.getMessage());

		// remove the 'pending' settings so that the still available settings continue to work
		viewSettings = new CurrentFunctionGraphViewSettings(view, viewSettings);
		return true;
	}

	private void doSetFunctionGraphData(FGData data) {
		// Note: we don't put the data in the cache here (it is done only on newly generated data)
		// because putting the same data that is already in the cache will cause it to be disposed.

		saveGraphSettingsForCurrentFunction();

		FGData oldData = functionGraphData;

		functionGraphData = data;

		view.setViewData(data);

		disposeIfNotInCache(oldData);

		restoreGraphSettingsForNewFunction();

		viewSettings = new CurrentFunctionGraphViewSettings(view, viewSettings);
		listener.dataChanged();
	}

	private boolean disposeIfNotInCache(FGData data) {
		// We only want to dispose of data that is not currently cached.  This can
		// happen if when it was removed from the cache, it was "in use" and could not
		// be disposed and now that it is no longer "in use", we can dispose it.
		Function function = data.getFunction();
		if (function != null && cache.getIfPresent(function) != data) {
			data.dispose();
			fgDataDisposeListener.accept(data, false);
			return true;
		}
		return false;
	}

	private void restoreGraphSettingsForNewFunction() {
		if (functionGraphData == null || !functionGraphData.hasResults()) {
			return;
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.restoreSettings();
	}

	private void saveGraphSettingsForCurrentFunction() {
		if (functionGraphData == null || !functionGraphData.hasResults() || isSnapshot()) {
			return;
		}

		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.saveSettings();
	}

	private boolean isSnapshot() {
		return !getNavigatable().isConnected();
	}

//==================================================================================================
//  Methods called by the vertices (actions and such)
//==================================================================================================

	/** Zooms so that the graph will fit completely into the size of the primary viewer */
	public void zoomOutGraph() {
		view.zoomOutGraph();
	}

	/** Zooms to the real size of the widgets */
	public void zoomInGraph() {
		view.zoomInGraph();
	}

	public void zoomToVertex(FGVertex v) {
		view.zoomToVertex(v);
	}

	public void zoomToWindow() {
		view.zoomToWindow();
	}

	public void setVertexViewMode(FGVertex vertex, boolean maximized) {
		view.setViewMode(vertex, maximized);
		minimalFormatManager.update();
	}

	public void repaint() {
		view.repaint();
	}

	public PluginTool getTool() {
		return env.getTool();
	}

	public Point getViewerPointFromVertexPoint(FGVertex vertex, Point point) {
		return view.translatePointFromVertexToViewSpace(vertex, point);
	}

	public Rectangle translateRectangleFromVertexToViewSpace(FGVertex vertex, Rectangle rectangle) {
		return view.translateRectangleFromVertexToViewSpace(vertex, rectangle);
	}

	public MouseEvent translateMouseEventFromVertexToViewSpace(FGVertex vertex, MouseEvent event) {
		return view.translateMouseEventFromVertexToViewSpace(vertex, event);
	}

	public ButtonPressedListener getSharedHighlighterButtonPressedListener() {
		return lazilyCreateSharedHighlightProvider();
	}

	public StringSelectionListener getSharedStringSelectionListener() {
		return sharedStringSelectionListener;
	}

	public FunctionGraphOptions getFunctionGraphOptions() {
		return functionGraphOptions;
	}

	public Color getMostRecentColor() {
		FGColorProvider colorProvider = env.getColorProvider();
		return colorProvider.getMostRecentColor();
	}

	public List<Color> getRecentColors() {
		FGColorProvider colorProvider = env.getColorProvider();
		return colorProvider.getRecentColors();
	}

	public void saveVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		FGColorProvider colorProvider = env.getColorProvider();
		colorProvider.saveVertexColors(vertex, settings);
	}

	public void restoreVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		FGColorProvider colorProvider = env.getColorProvider();
		colorProvider.loadVertexColors(vertex, settings);
	}

	public void removeColor(FGVertex vertex) {
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.clearVertexColor(vertex);
	}

	public FGColorProvider getColorProvider() {
		return env.getColorProvider();
	}

	public <T> T getService(Class<T> serviceClass) {
		PluginTool tool = env.getTool();
		return tool.getService(serviceClass);
	}

	/**
	 * Update the graph's notion of the current location based upon that of the Tool. This method is
	 * meant to be called from internal mutative operations.
	 */
	public void synchronizeProgramLocationAfterEdit() {
		// It is assumed that the provider's location is the correct location.
		viewSettings.setLocation(env.getGraphLocation());
	}

	/**
	 * A simple method to move the cursor to the given location in the currently graphed function.
	 * If the location is not in the current function, nothing will happen. 
	 * 
	 * @param location the location
	 */
	public void setLocation(ProgramLocation location) {
		if (viewContainsLocation(location)) {
			viewSettings.setLocation(location);
		}
	}

	public ProgramLocation getLocation() {
		return viewSettings.getLocation();
	}

	/**
	 * Will broadcast the given vertex location to the external system
	 *
	 * @param location the location coming from the vertex
	 */
	public void synchronizeProgramLocationToVertex(ProgramLocation location) {
		ProgramLocation viewSettingsLocation = viewSettings.getLocation();
		if (SystemUtilities.isEqual(viewSettingsLocation, location)) {
			return;
		}
		handleLocationChangedFromVertex(location);
	}

	private Cache<Function, FGData> buildCache(RemovalListener<Function, FGData> removalListener) {
		//@formatter:off
		return CacheBuilder
			  .newBuilder()
			  .maximumSize(5)
			  .removalListener(removalListener)
			  // Note: using soft values means that sometimes our data is reclaimed by the
			  //       Garbage Collector.  We don't want that, we wish to call dispose() on the data
			  //.softValues()
			  .build();
		//@formatter:on
	}

	// for testing
	void setCache(Cache<Function, FGData> cache) {
		this.cache.invalidateAll();
		this.cache = cache;
	}

	// open for testing
	void cacheValueRemoved(RemovalNotification<Function, FGData> notification) {
		disposeGraphDataIfNotInUse(notification.getValue());
	}

	void setFGDataDisposedListener(BiConsumer<FGData, Boolean> listener) {
		this.fgDataDisposeListener = listener != null ? listener : (data, evicted) -> {
			// dummy
		};
	}

	public Set<MarginProviderSupplier> getMarginProviderSuppliers() {
		return Collections.unmodifiableSet(marginProviders);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class FgHighlightProvider
			implements ListingHighlightProvider, ButtonPressedListener {
		private ListingMiddleMouseHighlightProvider highlighter;

		FgHighlightProvider(PluginTool tool, Component repaintComponent) {
			highlighter = new ListingMiddleMouseHighlightProvider(tool, repaintComponent);
		}

		@Override
		public Highlight[] createHighlights(String text, ListingField field, int cursorTextOffset) {
			return highlighter.createHighlights(text, field, cursorTextOffset);
		}

		@Override
		public void buttonPressed(ProgramLocation location, FieldLocation fieldLocation,
				ListingField field, MouseEvent event) {
			highlighter.buttonPressed(location, fieldLocation, field, event);
		}
	}
}
