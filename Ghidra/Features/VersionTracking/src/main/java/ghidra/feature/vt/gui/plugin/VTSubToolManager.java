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
package ghidra.feature.vt.gui.plugin;

import java.awt.Component;
import java.io.*;
import java.util.*;

import javax.swing.KeyStroke;

import org.jdom.Document;
import org.jdom.output.XMLOutputter;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.tool.util.DockingToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.duallisting.VTDualListingHighlightProvider;
import ghidra.feature.vt.gui.provider.functionassociation.VTFunctionAssociationContext;
import ghidra.feature.vt.gui.provider.onetomany.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.ToolUtils;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.GenericXMLOutputter;

public class VTSubToolManager implements VTControllerListener, OptionsChangeListener {
	private final static String SOURCE_TOOL_NAME = "Version Tracking (SOURCE TOOL)";
	private final static String DESTINATION_TOOL_NAME = "Version Tracking (DESTINATION TOOL)";

	private final VTPlugin plugin;
	private final VTController controller;
	private List<VTSubToolManagerListener> listeners = new ArrayList<>();
	private PluginTool sourceTool;
	private PluginTool destinationTool;
	private List<VersionTrackingSubordinatePluginX> pluginList = new ArrayList<>();
	private boolean processingOptions;

	VTSubToolManager(VTPlugin plugin) {
		this.plugin = plugin;
		this.controller = plugin.getController();
		controller.addListener(this);
	}

	Program openDestinationProgram(DomainFile domainFile, Component parent) {
		if (destinationTool == null) {
			destinationTool = createTool(DESTINATION_TOOL_NAME, false);
		}
		ProgramManager service = destinationTool.getService(ProgramManager.class);
		return service.openProgram(domainFile, parent);
	}

	Program openSourceProgram(DomainFile domainFile, Component parent) {
		if (sourceTool == null) {
			sourceTool = createTool(SOURCE_TOOL_NAME, true);
		}
		ProgramManager service = sourceTool.getService(ProgramManager.class);
		return service.openProgram(domainFile, parent);
	}

	void closeSourceProgram(Program source) {
		if (sourceTool != null) {
			ProgramManager service = sourceTool.getService(ProgramManager.class);
			service.closeProgram(source, true);
		}
	}

	void closeDestinationProgram(Program destination) {
		if (destinationTool != null) {
			ProgramManager service = destinationTool.getService(ProgramManager.class);
			service.closeProgram(destination, true);
		}
	}

	public void addListener(VTSubToolManagerListener listener) {
		listeners.add(listener);
	}

	public void removeListener(VTSubToolManagerListener listener) {
		listeners.remove(listener);
	}

	public void resetTools() {
		resetTool(DESTINATION_TOOL_NAME);
		resetTool(SOURCE_TOOL_NAME);
	}

	private void resetTool(String toolName) {
		String toolFileName = toolName + ToolUtils.TOOL_EXTENSION;
		File toolFile = new File(ToolUtils.getApplicationToolDirPath(), toolFileName);
		if (toolFile.exists()) {
			toolFile.delete();
		}
	}

	private PluginTool createTool(String toolName, boolean isSourceTool) {

		ToolTemplate toolTemplate = null;
		String toolFileName = toolName + ".tool";
		File toolFile = new File(ToolUtils.getApplicationToolDirPath(), toolFileName);

		if (toolFile.exists()) {
			toolTemplate = ToolUtils.readToolTemplate(toolFile);
		}

		if (toolTemplate == null) {
			toolTemplate = ToolUtils.readToolTemplate(toolFileName);
		}

		PluginTool newTool =
			(GhidraTool) toolTemplate.createTool(controller.getTool().getProject());
		try {
			VersionTrackingSubordinatePluginX pluginX =
				new VersionTrackingSubordinatePluginX(newTool, isSourceTool);
			pluginList.add(pluginX);
			newTool.addPlugin(pluginX);
		}
		catch (PluginException e) {
			Msg.error(this, "Failed to create subordinate tool: " + toolName);
		}

		newTool.setToolName(toolName);

		DockingActionIf save = getToolAction(newTool, "Save Tool");
		newTool.removeAction(save);

		createMarkupActions(newTool);

		newTool.setConfigChanged(false);

		ToolOptions options = newTool.getOptions(DockingToolConstants.KEY_BINDINGS);
		options.addOptionsChangeListener(this);

		// custom VT actions
		createMatchActions(newTool);

		return newTool;
	}

	private DockingActionIf getToolAction(PluginTool tool, String actionName) {
		Set<DockingActionIf> actions = tool.getDockingActionsByOwnerName(ToolConstants.TOOL_OWNER);
		for (DockingActionIf action : actions) {
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		throw new IllegalArgumentException("Unable to find Tool action '" + actionName + "'");
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (processingOptions) {
			return;
		}
		processingOptions = true;
		try {
			if (!(newValue instanceof KeyStroke)) {
				return;
			}
			KeyStroke keyStroke = (KeyStroke) newValue;
			if (sourceTool != null) {
				Options sourceOptions = sourceTool.getOptions(ToolConstants.KEY_BINDINGS);
				if (sourceOptions != options) {
					sourceOptions.setKeyStroke(optionName, keyStroke);
					sourceTool.refreshKeybindings();
					return;
				}
			}
			if (destinationTool != null) {
				Options destinationOptions = destinationTool.getOptions(ToolConstants.KEY_BINDINGS);
				if (destinationOptions != options) {
					destinationOptions.setKeyStroke(optionName, keyStroke);
					destinationTool.refreshKeybindings();
				}
			}
		}
		finally {
			processingOptions = false;
		}
	}

	private void createMatchActions(final PluginTool newTool) {
		newTool.setMenuGroup(new String[] { VTPlugin.MATCH_POPUP_MENU_NAME }, "1", "1");
		newTool.setMenuGroup(new String[] { VTPlugin.MARKUP_POPUP_MENU_NAME }, "1", "2");

		newTool.addAction(new MatchActionWrapper(plugin, new AcceptMatchAction(controller)));
		newTool.addAction(new MatchActionWrapper(plugin, new ApplyMatchAction(controller)));
		newTool.addAction(new MatchActionWrapper(plugin, new RejectMatchAction(controller)));

		newTool.addAction(new MatchActionWrapper(plugin, new ChooseMatchTagAction(controller)));

		CreateManualMatchFromToolsAction createMatchAction =
			new CreateManualMatchFromToolsAction(plugin);
		CreateAndAcceptManualMatchFromToolsAction createAndAcceptMatchAction =
			new CreateAndAcceptManualMatchFromToolsAction(plugin);
		CreateAndApplyManualMatchFromToolsAction createAndApplyMatchAction =
			new CreateAndApplyManualMatchFromToolsAction(plugin);

		MatchActionWrapper selectMatchAction =
			new MatchActionWrapper(plugin, new SelectExistingMatchAction(controller)) {
				@Override
				public ActionContext createActionContext(docking.ActionContext originalContext) {
					SubToolContext subToolContext = getSubToolContext();
					List<VTMatch> list = new ArrayList<>();
					VTMatch match = subToolContext.getMatch();
					if (match == null) {
						return null;
					}

					list.add(match);
					return new VTFunctionAssociationContext(newTool, getSourceFunction(),
						getDestinationFunction(), match);
				}
			};

		// put the create and select actions in the same group, as they are
		// different than the
		// actions that modify matches
		MenuData createActionMenuData = createMatchAction.getPopupMenuData();
		MenuData selectMenuData = selectMatchAction.getPopupMenuData();
		selectMenuData.setMenuGroup(createActionMenuData.getMenuGroup());

		newTool.addAction(createMatchAction);
		newTool.addAction(createAndAcceptMatchAction);
		newTool.addAction(createAndApplyMatchAction);
		newTool.addAction(selectMatchAction);
	}

	private void createMarkupActions(PluginTool tool) {

		tool.addAction(fixupMarkupActionMenuPath(
			new ApplyUsingOptionsAndForcingMarkupItemAction(controller, false)));
		tool.addAction(
			fixupMarkupActionMenuPath(new ApplyAndAddMarkupItemAction(controller, false)));
		tool.addAction(
			fixupMarkupActionMenuPath(new ApplyAndAddAsPrimaryMarkupItemAction(controller, false)));
		tool.addAction(
			fixupMarkupActionMenuPath(new ApplyAndReplaceMarkupItemAction(controller, false)));
		tool.addAction(fixupMarkupActionMenuPath(new DontKnowMarkupItemAction(controller, false)));
		tool.addAction(fixupMarkupActionMenuPath(new DontCareMarkupItemAction(controller, false)));
		tool.addAction(fixupMarkupActionMenuPath(new RejectMarkupItemAction(controller, false)));
		tool.addAction(fixupMarkupActionMenuPath(new ResetMarkupItemAction(controller, false)));
		tool.addAction(fixupMarkupActionMenuPath(new EditMarkupAddressAction(controller, true)));
	}

	private DockingActionIf fixupMarkupActionMenuPath(DockingAction action) {
		MenuData menuData = action.getPopupMenuData();
		String[] menuPath = menuData.getMenuPath();

		String[] newPath = new String[menuPath.length + 1];
		newPath[0] = VTPlugin.MARKUP_POPUP_MENU_NAME;
		for (int i = 0; i < menuPath.length; i++) {
			newPath[i + 1] = menuPath[i];
		}

		menuData.setMenuPath(newPath);

		return action;
	}

	private void closeSessionLater() {
		SystemUtilities.runSwingLater(() -> controller.closeVersionTrackingSession());

	}

	private List<DomainFile> getChangedPrograms(PluginTool subTool) {
		List<DomainFile> domainFiles = new ArrayList<>();
		if (subTool != null) {
			ProgramManager service = subTool.getService(ProgramManager.class);
			Program[] allOpenPrograms = service.getAllOpenPrograms();
			for (Program program : allOpenPrograms) {
				if (program.isChanged()) {
					domainFiles.add(program.getDomainFile());
				}
			}
		}
		return domainFiles;
	}

	@Override
	public void sessionChanged(VTSession session) {
		if (session != null) {
			if (sourceTool == null) {
				sourceTool = createTool(SOURCE_TOOL_NAME, true);
			}
			if (destinationTool == null) {
				destinationTool = createTool(DESTINATION_TOOL_NAME, false);
			}
			closeAllButSessionProgram(sourceTool, controller.getSourceProgram());
			closeAllButSessionProgram(destinationTool, controller.getDestinationProgram());
			sourceTool.setVisible(true);
			destinationTool.setVisible(true);
			for (VersionTrackingSubordinatePluginX pluginX : pluginList) {
				pluginX.update();
			}
			return;
		}
		saveSubordinateToolConfig(sourceTool);
		saveSubordinateToolConfig(destinationTool);
		pluginList.clear();
		sourceTool.exit();
		destinationTool.exit();
		sourceTool = null;
		destinationTool = null;
	}

	private void closeAllButSessionProgram(PluginTool tool, Program program) {
		ProgramManager service = tool.getService(ProgramManager.class);
		program.addConsumer(this);
		service.closeAllPrograms(true);
		service.openProgram(program);
		program.release(this);
	}

	@Override
	public void sessionUpdated(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(VTChangeManager.DOCR_VT_MARKUP_ITEM_STATUS_CHANGED)) {
			CodeViewerService service = sourceTool.getService(CodeViewerService.class);
			if (service == null) {
				return;
			}
			for (VersionTrackingSubordinatePluginX pluginX : pluginList) {
				pluginX.update();
			}
			ListingPanel listingPanel = service.getListingPanel();
			listingPanel.repaint();
		}
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			// This kicks the sub-tool highlight providers so each gets fresh
			// markup item information.
			for (VersionTrackingSubordinatePluginX pluginX : pluginList) {
				pluginX.update();
			}
		}
	}

	@Override
	public void disposed() {
		// nothing to do; handled in sessionChanged()
	}

	private void saveSubordinateToolConfig(PluginTool t) {
		String toolName = t.getName();
		String toolFileName = toolName + ".tool";
		File toolFile = new File(ToolUtils.getApplicationToolDirPath(), toolFileName);

		try {
			OutputStream os = new FileOutputStream(toolFile);
			Document doc = new Document(t.getToolTemplate(true).saveToXml());
			XMLOutputter xmlOut = new GenericXMLOutputter();
			xmlOut.output(doc, os);
			os.close();
		}
		catch (IOException e) {
			Msg.showError(this, t.getToolFrame(), "Version Tracking",
				"Failed to save source tool configuration\nFile: " + toolName + "\n" +
					e.getMessage());
		}
		t.setConfigChanged(false);
	}

	public List<DomainFile> getChangedProgramsInSourceTool() {
		return getChangedPrograms(sourceTool);
	}

	public List<DomainFile> getChangedProgramsInDestinationTool() {
		return getChangedPrograms(destinationTool);
	}

	@Override
	public void matchSelected(MatchInfo matchInfo) {
		if (matchInfo != null) {
			VTMatch match = matchInfo.getMatch();
			VTAssociation association = match.getAssociation();
			Address sourceAddress = association.getSourceAddress();
			Address destinationAddress = association.getDestinationAddress();
			Program sourceProgram = controller.getSourceProgram();
			Program destinationProgram = controller.getDestinationProgram();

			gotoInTool(sourceTool, sourceProgram, sourceAddress);
			gotoInTool(destinationTool, destinationProgram, destinationAddress);
		}
		for (VersionTrackingSubordinatePluginX pluginX : pluginList) {
			pluginX.update();
		}
	}

	public void setMatch(VTMatch match) {
		VTAssociation association = match.getAssociation();
		Address sourceAddress = association.getSourceAddress();
		Address destinationAddress = association.getDestinationAddress();
		Program sourceProgram = controller.getSourceProgram();
		Program destinationProgram = controller.getDestinationProgram();

		gotoInTool(sourceTool, sourceProgram, sourceAddress);
		gotoInTool(destinationTool, destinationProgram, destinationAddress);
		for (VTSubToolManagerListener listener : listeners) {
			listener.setSelectedMatch(match);
		}
	}

	private void gotoInTool(PluginTool tool, Program program, Address address) {
		GoToService service = tool.getService(GoToService.class);
		service.goTo(address, program);
	}

	// don't end the name in Plugin so that it won't be found by the class
	// searcher.
	//@formatter:off
	@PluginInfo(
		status = PluginStatus.HIDDEN,
		packageName = VersionTrackingPluginPackage.NAME,
		category = "Version Tracking",
		shortDescription = "",
		description = "",
		servicesRequired = { ProgramManager.class },
		eventsConsumed = { ProgramLocationPluginEvent.class, ProgramActivatedPluginEvent.class }
	)
	//@formatter:on
	class VersionTrackingSubordinatePluginX extends Plugin {

		private VTMatchOneToManyTableProvider provider;
		private final boolean isSourceTool;
		private boolean tracking = true;
		private VTDualListingHighlightProvider highlightProvider;

		public VersionTrackingSubordinatePluginX(PluginTool tool, boolean isSourceTool) {
			super(tool);
			this.isSourceTool = isSourceTool;
			provider = isSourceTool
					? new VTMatchSourceTableProvider(tool, controller, VTSubToolManager.this)
					: new VTMatchDestinationTableProvider(tool, controller, VTSubToolManager.this);

			highlightProvider = new VTDualListingHighlightProvider(controller, isSourceTool);
		}

		@Override
		protected void dispose() {
			provider.disposed();
		}

		public void update() {
			ProgramManager service = tool.getService(ProgramManager.class);
			Program currentProgram = service.getCurrentProgram();
			Program vtProgram = getVTProgram();
			setTracking(currentProgram == vtProgram);
			highlightProvider.updateMarkup();
			updateListing();
		}

		public void updateMarkup(VTMarkupItem markupItem) {
			highlightProvider.setMarkupItem(markupItem);
			if (markupItem != null) {
				Program program = (highlightProvider.isSource()) ? controller.getSourceProgram()
						: controller.getDestinationProgram();
				ProgramLocation location =
					(highlightProvider.isSource()) ? markupItem.getSourceLocation()
							: markupItem.getDestinationLocation();
				GoToService goToService = tool.getService(GoToService.class);
				if ((goToService != null) && (location != null)) {
					goToService.goTo(location, program);
				}
			}
			CodeViewerService codeViewerService = tool.getService(CodeViewerService.class);
			if (codeViewerService != null) {
				codeViewerService.updateDisplay();
			}
		}

		@Override
		protected boolean canClose() {
			if (isToolExecutingCommand(sourceTool)) {
				VTPlugin.showBusyToolMessage(sourceTool);
				return false;
			}
			else if (isToolExecutingCommand(destinationTool)) {
				VTPlugin.showBusyToolMessage(destinationTool);
				return false;
			}

			int resp = OptionDialog.showYesNoDialog(tool.getToolFrame(), "Version Tracking",
				"Closing this tool will terminate the active Version " +
					"Tracking Session.\nContinue closing tool?");

			if (resp != OptionDialog.NO_OPTION) {
				closeSessionLater();
			}
			return false;
		}

		@Override
		protected boolean canCloseDomainObject(DomainObject dObj) {
			Program sourceProgram = controller.getSourceProgram();
			Program destintationProgram = controller.getDestinationProgram();
			if (dObj != sourceProgram && dObj != destintationProgram) {
				return true;
			}
			int resp = OptionDialog.showYesNoDialog(tool.getToolFrame(), "Version Tracking",
				"Closing this program will terminate " +
					"the active Version Tracking Session.\nContinue?");

			if (resp != OptionDialog.NO_OPTION) {
				closeSessionLater();
			}
			return false;
		}

		@Override
		public void processEvent(PluginEvent event) {
			if (event instanceof ProgramActivatedPluginEvent) {
				ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
				Program currentProgram = ev.getActiveProgram();
				Program vtProgram = getVTProgram();
				// vtProgram is null at beginning, but start tracking to true;
				setTracking(vtProgram == currentProgram && currentProgram != null);
			}
			else if (event instanceof ProgramLocationPluginEvent) {
				if (!tracking) {
					return;
				}
				ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
				ProgramLocation currentLocation = ev.getLocation();
				Address address = currentLocation == null ? null : currentLocation.getAddress();
				provider.setAddress(getFunctionOrDataStartAddress(address));
			}
		}

		private Address getFunctionOrDataStartAddress(Address address) {
			if (address == null) {
				return null;
			}
			Program program = getVTProgram();
			if (program == null) {
				return null;
			}
			Function function = program.getFunctionManager().getFunctionContaining(address);
			if (function == null) {
				Data data = program.getListing().getDataContaining(address);
				if (data == null) {
					return null;
				}
				if (data.isPointer()) {
					// follow external reference (handle external linkage location)
					Reference ref = data.getPrimaryReference(0);
					if (ref != null && ref.isExternalReference()) {
						return ref.getToAddress();
					}
				}
				return data.getAddress();
			}
			else if (function.isThunk()) {
				// follow thunk (handle internal/external linkage location)
				function = function.getThunkedFunction(true);
			}
			return function.getEntryPoint();
		}

		private void setTracking(boolean b) {
			this.tracking = b;
			if (!tracking) {
				provider.setAddress(null);
				setHighlightProvider(null, highlightProvider);
			}
			else {
				setHighlightProvider(highlightProvider, null);
			}
		}

		private void setHighlightProvider(VTDualListingHighlightProvider newProvider,
				VTDualListingHighlightProvider lastProvider) {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service == null) {
				return;
			}

			ListingPanel listingPanel = service.getListingPanel();
			if (newProvider == null) {
				highlightProvider.setListingPanel(null);
				listingPanel.getFormatManager().removeHighlightProvider(lastProvider);
			}
			else {
				newProvider.setListingPanel(listingPanel);

				// be sure not to add the highlight provider twice!
				listingPanel.getFormatManager().removeHighlightProvider(newProvider);
				listingPanel.getFormatManager().addHighlightProvider(newProvider);
			}
		}

		private void updateListing() {
			CodeViewerService service = tool.getService(CodeViewerService.class);
			if (service == null) {
				return;
			}
			service.updateDisplay();
		}

		private Program getVTProgram() {
			if (isSourceTool) {
				return controller.getSourceProgram();
			}
			return controller.getDestinationProgram();
		}
	}

	@Override
	public void markupItemSelected(VTMarkupItem markupItem) {
		for (VersionTrackingSubordinatePluginX pluginX : pluginList) {
			pluginX.updateMarkup(markupItem);
		}
	}

	@Override
	public void optionsChanged(Options options) {
		// doesn't use options currently
	}

	/**
	 * Get's the source tool from the VT session.
	 * 
	 * @return The source tool from the VT session.
	 */
	PluginTool getSourceTool() {
		return sourceTool;
	}

	/**
	 * Get's the destination tool from the VT session.
	 * 
	 * @return The destination tool from the VT session.
	 */
	PluginTool getDestinationTool() {
		return destinationTool;
	}

	/**
	 * Checks whether or not the given tool is currently executing a background
	 * task.
	 * 
	 * @param tool
	 *            The tool to check.
	 * @return True is the given tool is currently executing a background task;
	 *         False otherwise.
	 */
	boolean isToolExecutingCommand(PluginTool tool) {
		return tool != null && tool.isExecutingCommand();
	}

	void gotoSourceLocation(ProgramLocation location) {
		GoToService service = sourceTool.getService(GoToService.class);
		service.goTo(location);
	}

	void gotoDestinationLocation(ProgramLocation location) {
		GoToService service = destinationTool.getService(GoToService.class);
		service.goTo(location);
	}

	ProgramLocation getSourceLocation() {
		GoToService service = sourceTool.getService(GoToService.class);
		Navigatable navigatable = service.getDefaultNavigatable();
		return navigatable.getLocation();
	}

	ProgramLocation getDestinationLocation() {
		GoToService service = destinationTool.getService(GoToService.class);
		Navigatable navigatable = service.getDefaultNavigatable();
		return navigatable.getLocation();
	}

	Function getSourceFunction() {
		VTSession session = controller.getSession();
		if (session == null) {
			return null;
		}

		Program sourceProgram = session.getSourceProgram();
		ProgramManager service = sourceTool.getService(ProgramManager.class);
		Program program = service.getCurrentProgram();
		if (sourceProgram != program) {
			return null; // the user has changed programs
		}

		ProgramLocation location = getSourceLocation();
		if (location == null) {
			return null;
		}

		FunctionManager functionManager = program.getFunctionManager();
		return functionManager.getFunctionContaining(location.getAddress());
	}

	Function getDestinationFunction() {
		VTSession session = controller.getSession();
		if (session == null) {
			return null;
		}

		Program sourceProgram = session.getDestinationProgram();
		ProgramManager service = destinationTool.getService(ProgramManager.class);
		Program program = service.getCurrentProgram();
		if (sourceProgram != program) {
			return null; // the user has changed programs
		}

		ProgramLocation location = getDestinationLocation();
		if (location == null) {
			return null;
		}

		FunctionManager functionManager = program.getFunctionManager();
		return functionManager.getFunctionContaining(location.getAddress());
	}

	boolean isDestinationCursorOnScreen() {
		CodeViewerService service = destinationTool.getService(CodeViewerService.class);
		return isCursorOnScreen(service);
	}

	boolean isSourceCursorOnScreen() {
		CodeViewerService service = sourceTool.getService(CodeViewerService.class);
		return isCursorOnScreen(service);
	}

	private boolean isCursorOnScreen(CodeViewerService service) {
		FieldPanel fieldPanel = service.getFieldPanel();
		int cursorOffset = fieldPanel.getCursorOffset();
		return cursorOffset >= 0; // negative offset means offscreen
	}

	/**
	 * Gets the address set for the current selection in the tool.
	 * 
	 * @param tool
	 *            the tool
	 * @return the current selection or null.
	 */
	private AddressSetView getSelectionInTool(PluginTool tool) {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null) {
			return null;
		}
		FieldSelection selection = service.getFieldPanel().getSelection();
		AddressIndexMap addressIndexMap = service.getListingPanel().getAddressIndexMap();
		AddressSet addressSet = addressIndexMap.getAddressSet(selection);
		return addressSet;
	}

	/**
	 * Sets the address set to be the selection in the tool.
	 * 
	 * @param tool
	 *            the tool
	 * @param set
	 *            the addressSet to use for the selection
	 */
	private void setSelectionInTool(PluginTool tool, AddressSetView addressSet) {
		ProgramSelection programSelection = new ProgramSelection(addressSet);
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null) {
			return;
		}
		service.getNavigatable().setSelection(programSelection);
	}

	/**
	 * Gets the address set for the current selection in the Source Tool.
	 * 
	 * @return the current selection or null.
	 */
	AddressSetView getSelectionInSourceTool() {
		return getSelectionInTool(sourceTool);
	}

	/**
	 * Gets the address set for the current selection in the Destination Tool.
	 * 
	 * @return the current selection or null.
	 */
	AddressSetView getSelectionInDestinationTool() {
		return getSelectionInTool(destinationTool);
	}

	public void setSelectionInDestinationTool(AddressSetView destinationSet) {
		setSelectionInTool(destinationTool, destinationSet);
	}

	public void setSelectionInSourceTool(AddressSetView sourceSet) {
		setSelectionInTool(sourceTool, sourceSet);
	}

	public ColorizingService getSourceColorizingService() {
		return sourceTool.getService(ColorizingService.class);
	}

	public ColorizingService getDestinationColorizingService() {
		return destinationTool.getService(ColorizingService.class);
	}
}
