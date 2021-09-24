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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

import com.google.common.cache.*;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.ListingHighlightProvider;
import ghidra.app.plugin.core.functiongraph.*;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.services.ButtonPressedListener;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.graph.viewer.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;

public class FGController implements ProgramLocationListener, ProgramSelectionListener {

	private final FunctionGraphPlugin plugin;
	private FGProvider provider;
	private final FGModel model;
	private final FGView view;

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

	private SharedHighlightProvider sharedHighlightProvider;
	private StringSelectionListener sharedStringSelectionListener =
		string -> provider.setClipboardStringContent(string);

	private Cache<Function, FGData> cache;

	public FGController(FGProvider provider, FunctionGraphPlugin plugin) {
		this.provider = provider;
		this.plugin = plugin;
		this.cache = buildCache(this::cacheValueRemoved);
		this.model = new FGModel(this);
		this.view = new FGView(this, model.getTaskMonitorComponent());

		functionGraphOptions = plugin.getFunctionGraphOptions();
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
		return true;
	}

	private FormatManager createMinimalFormatManager() {
		FormatManager userDefinedFormat = plugin.getUserDefinedFormat();
		if (userDefinedFormat != null) {
			return userDefinedFormat;
		}
		return createDefaultFormat();
	}

	private FormatManager createFullFormatManager() {
		CodeViewerService codeViewer = plugin.getTool().getService(CodeViewerService.class);
		return codeViewer.getFormatManager();
	}

	public FormatManager getMinimalFormatManager() {
		if (minimalFormatManager == null) {
			setMinimalFormatManager(createMinimalFormatManager());
		}
		return minimalFormatManager;
	}

	private void setMinimalFormatManager(FormatManager formatManager) {
		this.minimalFormatManager = formatManager;
		SharedHighlightProvider highlightProvider = lazilyCreateSharedHighlightProvider();
		minimalFormatManager.addHighlightProvider(highlightProvider);
	}

	public FormatManager getFullFormatManager() {
		if (fullFormatManager == null) {
			fullFormatManager = createFullFormatManager();
		}
		return fullFormatManager;
	}

	private FormatManager getDefaultFormatManager() {
		if (defaultFormatManager == null) {
			defaultFormatManager = createDefaultFormat();
		}
		return defaultFormatManager;
	}

	private SharedHighlightProvider lazilyCreateSharedHighlightProvider() {
		if (sharedHighlightProvider != null) {
			return sharedHighlightProvider;
		}
		sharedHighlightProvider =
			new SharedHighlightProvider(plugin.getTool(), provider.getComponent());
		return sharedHighlightProvider;
	}

	public void formatChanged() {
		setMinimalFormatManager(plugin.getUserDefinedFormat());
		view.repaint();
	}

	public Navigatable getNavigatable() {
		return provider;
	}

	private FormatManager createDefaultFormat() {
		OptionsService options = plugin.getTool().getService(OptionsService.class);
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
		boolean updateHistory = false;
		if (vertexChanged) {
			if (shouldSaveVertexChanges()) {
				// put the navigation on the history stack if we've changed nodes (this is the
				// location we are leaving)
				provider.saveLocationToHistory();
				updateHistory = true;
			}
			lastUserNavigatedVertex = newFocusedVertex;
		}

		viewSettings.setLocation(loc);
		provider.graphLocationChanged(loc);

		if (updateHistory) {
			// put the new location on the history stack now that we've updated the provider
			provider.saveLocationToHistory();
		}
	}

	private boolean shouldSaveVertexChanges() {
		return functionGraphOptions
				.getNavigationHistoryChoice() == NavigationHistoryChoices.VERTEX_CHANGES;
	}

	@Override
	public void programSelectionChanged(ProgramSelection selection) {
		// We need to translate the given selection (which is from a single vertex) to the current
		// overall selection for the graph (which includes the selection from all vertices).  We
		// do this so that a selection change in one vertex does not clear the selection in
		// other vertices
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		ProgramSelection fullSelection = graph.getProgramSelectionForAllVertices();

		// push the user changes up to the provider
		viewSettings.setSelection(fullSelection);
		provider.graphSelectionChanged(fullSelection);
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
//  Methods call by the providers
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

	public boolean isSatelliteDocked() {
		return view.isSatelliteDocked();
	}

	public void satelliteProviderShown() {
		// note: always show the primary provider when the satellite is shown
		if (provider.isVisible()) {
			return; // nothing to do
		}

		// We do this later because it is possible during initialization that the provider is
		// not 'inTool' because of how XML gets restored.  So, just do it later--it's less code.
		SwingUtilities.invokeLater(() -> provider.setVisible(true));
	}

	public void primaryProviderHidden() {
		clear();
	}

	public void setPopupsVisible(boolean visible) {
		view.setPopupsVisible(visible);
		provider.setPopupsVisible(visible);
	}

	public boolean arePopupsEnabled() {
		return view.arePopupsEnabled();
	}

	public FGVertex getFocusedVertex() {
		if (!hasResults()) {
			return null;
		}

		return view.getFocusedVertex();
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

	public void requestFocus() {
		view.requestFocus();
	}

	public void cleanup() {
		clear();
		disposeCache();
		model.cleanup();
		view.cleanup();
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
		provider.refreshAndKeepPerspective();
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
		ProgramLocation externalLocation = plugin.getProgramLocation();
		if (!externalLocation.getAddress().equals(location.getAddress())) {
			provider.graphLocationChanged(location);
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
		view.refreshDisplayWithoutRebuilding();
	}

	public void refreshDisplayForAddress(Address address) {
		view.refreshDisplayForAddress(address);
	}

	public Program getProgram() {
		return provider.getProgram();
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

	public JComponent getViewComponent() {
		return view.getViewComponent();
	}

	public void changeLayout(FGLayoutProvider newLayout) {
		FGLayoutProvider previousLayout = (FGLayoutProvider) view.getLayoutProvider();
		view.setLayoutProvider(newLayout);

		if (previousLayout == null) {
			provider.refreshAndResetPerspective();
			return;
		}

		String previousLayoutName = previousLayout.getLayoutName();
		String newLayoutName = newLayout.getLayoutName();
		if (previousLayoutName.equals(newLayoutName)) {
			view.relayout();
		}
		else {
			provider.refreshAndResetPerspective();
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

		PluginTool tool = plugin.getTool();
		SetFormatDialogComponentProvider setFormatDialog =
			new SetFormatDialogComponentProvider(getDefaultFormatManager(), minimalFormatManager,
				tool, provider.getProgram(), vertex.getAddresses());
		tool.showDialog(setFormatDialog);
		FormatManager newFormatManager = setFormatDialog.getNewFormatManager();
		if (newFormatManager == null) {
			return;
		}

		SaveState saveState = new SaveState();
		newFormatManager.saveState(saveState);
		minimalFormatManager.readState(saveState);
		plugin.setUserDefinedFormat(minimalFormatManager);
		view.repaint();
	}

	public void showXRefsDialog() {
		PluginTool tool = plugin.getTool();
		Program program = plugin.getCurrentProgram();
		List<Reference> references = getXReferencesToGraph();
		XRefChooserDialog chooserDialog = new XRefChooserDialog(references, program, tool);

		tool.showDialog(chooserDialog, provider);
		Reference reference = chooserDialog.getSelectedReference();
		if (reference == null) {
			return; // the user cancelled
		}

		internalGoTo(new ProgramLocation(program, reference.getFromAddress()), program);
	}

	private List<Reference> getXReferencesToGraph() {
		Program program = plugin.getCurrentProgram();
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
	 * Signals that something major has changed for the program and we don't know where, so
	 * clear all cached functions for the given program.
	 *
	 * BLEH!: I don't like clearing the cache this way...another options is to mark all cached
	 *       values as stale, somehow.  If we did this, then when the view reuses the cached
	 *       data, it could signal to the user that the graph is out-of-date.
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

//==================================================================================================
//  Methods call by the model
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
		provider.functionGraphDataChanged();
	}

	private boolean disposeIfNotInCache(FGData data) {
		// We only want to dispose of data that is not currently cached.  This can
		// happen if when it was removed from the cache, it was "in use" and could not
		// be disposed and now that it is no longer "in use", we can dispose it.
		Function function = data.getFunction();
		if (function != null && cache.getIfPresent(function) != data) {
			data.dispose();
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
		return !provider.isConnected();
	}

//==================================================================================================
//  Methods call by the vertices (actions and such)
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
		return provider.getTool();
	}

	public FGProvider getProvider() {
		return provider;
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
		FGColorProvider colorProvider = plugin.getColorProvider();
		return colorProvider.getMostRecentColor();
	}

	public List<Color> getRecentColors() {
		FGColorProvider colorProvider = plugin.getColorProvider();
		return colorProvider.getRecentColors();
	}

	public void saveVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		FGColorProvider colorProvider = plugin.getColorProvider();
		colorProvider.saveVertexColors(vertex, settings);
	}

	public void restoreVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		FGColorProvider colorProvider = plugin.getColorProvider();
		colorProvider.loadVertexColors(vertex, settings);
	}

	public void removeColor(FGVertex vertex) {
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.clearVertexColor(vertex);
	}

	public FGColorProvider getColorProvider() {
		return plugin.getColorProvider();
	}

	/**
	 * Update the graph's notion of the current location based upon that of the Tool.  This
	 * method is meant to be called from internal mutative operations.
	 */
	public void synchronizeProgramLocationAfterEdit() {
		// It is assumed that the provider's location is the correct location.
		viewSettings.setLocation(provider.getLocation());
	}

	/**
	 * Will broadcast the given vertex location to the external system
	 * @param location the location coming from the vertex
	 */
	public void synchronizeProgramLocationToVertex(ProgramLocation location) {
		ProgramLocation viewSettingsLocation = viewSettings.getLocation();
		if (SystemUtilities.isEqual(viewSettingsLocation, location)) {
			return;
		}
		handleLocationChangedFromVertex(location);
	}

	public void internalGoTo(ProgramLocation programLocation, Program program) {
		provider.internalGoTo(programLocation, program);
	}

	private Cache<Function, FGData> buildCache(RemovalListener<Function, FGData> listener) {
		//@formatter:off
		return CacheBuilder
			  .newBuilder()
			  .maximumSize(5)
			  .removalListener(listener)
			  // Note: using soft values means that sometimes our data is reclaimed by the 
			  //       Garbage Collector.  We don't want that, we wish to call dispose() on the data
			  //.softValues() 
			  .build();
		//@formatter:on
	}

	private void cacheValueRemoved(RemovalNotification<Function, FGData> notification) {
		disposeGraphDataIfNotInUse(notification.getValue());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class SharedHighlightProvider
			implements HighlightProvider, ButtonPressedListener {
		private ListingHighlightProvider highlighter;

		SharedHighlightProvider(PluginTool tool, Component repaintComponent) {
			highlighter = new ListingHighlightProvider(tool, repaintComponent);
		}

		@Override
		public Highlight[] getHighlights(String text, Object obj,
				Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {
			return highlighter.getHighlights(text, obj, fieldFactoryClass, cursorTextOffset);
		}

		@Override
		public void buttonPressed(ProgramLocation location, FieldLocation fieldLocation,
				ListingField field, MouseEvent event) {
			highlighter.buttonPressed(location, fieldLocation, field, event);
		}
	}
}
