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
package ghidra.framework.main;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JFrame;
import javax.swing.JPanel;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import db.buffers.DataBuffer;
import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.util.AnimationUtils;
import docking.util.image.ToolIconURL;
import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import generic.util.WindowUtilities;
import ghidra.app.plugin.GenericPluginCategoryNames;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.Application;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.client.*;
import ghidra.framework.main.datatree.ChangedFilesDialog;
import ghidra.framework.main.datatree.CheckInTask;
import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;
import ghidra.framework.main.logviewer.model.ChunkModel;
import ghidra.framework.main.logviewer.model.ChunkReader;
import ghidra.framework.main.logviewer.ui.FileViewer;
import ghidra.framework.main.logviewer.ui.FileWatcher;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.*;
import ghidra.util.bean.GGlassPane;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import help.Help;
import help.HelpService;

/**
 * Tool that serves as the the Ghidra Project Window. Only those plugins that
 * implement the FrontEndable interface may be <i>directly</i> added to this
 * tool by the user. Other plugins that are not marked as FrontEndable may get
 * pulled in because the FrontEndable plugins depend on them. These plugins are
 * aware of what tool they live in so that they can behave in the appropriate
 * manner.
 */
public class FrontEndTool extends PluginTool implements OptionsChangeListener {
	public static final String DEFAULT_TOOL_LAUNCH_MODE = "Default Tool Launch Mode";
	public static final String AUTOMATICALLY_SAVE_TOOLS = "Automatically Save Tools";
	private static final String USE_ALERT_ANIMATION_OPTION_NAME = "Use Notification Animation";
	private static final String SHOW_TOOLTIPS_OPTION_NAME = "Show Tooltips";

	// TODO: Experimental Option !!
	private static final String ENABLE_COMPRESSED_DATABUFFER_OUTPUT =
		"Use DataBuffer Output Compression";

	private static final String RESTORE_PREVIOUS_PROJECT_NAME = "Restore Previous Project";
	private boolean shouldRestorePreviousProject;

	private static final int MIN_HEIGHT = 600;

	/**
	 * Preference name for whether to show the "What's New" help page when the
	 * Ghidra Project Window is displayed.
	 */
	private final static String GHIDRA_SHOW_WHATS_NEW = "GhidraShowWhatsNew";

	/**
	 * Window state preference for the location of the divider for the split
	 * pane in the Ghidra Project Window. The divider is visible when another
	 * project view is opened.
	 */
	private final static String GHIDRA_MAIN_PANEL_DIVIDER_LOC = "GhidraMainPanelDividerLocation";

	private static final String FRONT_END_TOOL_XML_NAME = "FRONTEND";
	private static final String VERSION_ATTRIBUTE_NAME = "VERSION";
	private static final String FRONT_END_FILE_NAME = "FrontEndTool.xml";
	private static final String CONFIGURE_GROUP = "Configure";
	private static final File TOOL_FILE =
		new File(Application.getUserSettingsDirectory(), FRONT_END_FILE_NAME);

	private WeakSet<ProjectListener> listeners;
	private FrontEndPlugin plugin;

	private DefaultLaunchMode defaultLaunchMode = DefaultLaunchMode.DEFAULT;

	private ComponentProvider compProvider;
	private LogComponentProvider logProvider;

	private WindowListener windowListener;
	private DockingAction configureToolAction;
	private PluginClassManager pluginClassManager;

	/**
	 * Construct a new Ghidra Project Window.
	 *
	 * @param pm project manager
	 */
	public FrontEndTool(ProjectManager pm) {
		super(null, pm, null, null /*tool template*/, false, false, false);
		setToolName("Project Window");

		listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		installFrontEndPlugins();
		createActions();
		loadToolConfigurationFromDisk();

		ensureSize();
		windowListener = new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				setDividerLocation();
				getToolFrame().removeWindowListener(windowListener);
			}
		};
		JFrame toolFrame = getToolFrame();
		toolFrame.addWindowListener(windowListener);

		AppInfo.setFrontEndTool(this);
		AppInfo.setActiveProject(getProject());

		initFrontEndOptions();
	}

	@Override
	protected void dispose() {
		super.dispose();

		if (logProvider != null) {
			logProvider.dispose();
		}
	}

	private void ensureSize() {
		JFrame frame = getToolFrame();
		Dimension size = frame.getSize();
		if (size.height < MIN_HEIGHT) {
			size.height = MIN_HEIGHT;
			Point center = WindowUtilities.centerOnScreen(size);
			frame.setBounds(center.x, center.y, size.width, size.height);
		}
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		if (pluginClassManager == null) {
			pluginClassManager = new PluginClassManager(ApplicationLevelPlugin.class, null);
		}
		return pluginClassManager;
	}

	public void selectFiles(Set<DomainFile> files) {
		plugin.selectFiles(files);
	}

	private void loadToolConfigurationFromDisk() {

		Element root = getToolFileXml();
		if (root == null) {
			// not file from which to check the version; perform default initialization
			installDefaultApplicationLevelPlugins();
			return;
		}

		GhidraToolTemplate template = new GhidraToolTemplate((Element) root.getChildren().get(0),
			TOOL_FILE.getAbsolutePath());
		refresh(template);
	}

	private Element getToolFileXml() {
		if (!TOOL_FILE.exists()) {
			return null;
		}

		try (InputStream is = new FileInputStream(TOOL_FILE)) {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			return sax.build(is).getRootElement();
		}
		catch (IOException | JDOMException e) {
			Msg.showError(this, null, "Error", "Error reading front end configuration", e);
		}
		return null;
	}

	@Override
	protected boolean doSaveTool() {
		// This method is overridden to allow the FrontEndTool to perform custom saving.
		// The super.doSaveTool is designed to save tools to the user's tool chest directory. The 
		// FrontEndTool saves its state directly in the user's settings directory and includes
		// the entire project's state such as what tools were running and data states for each
		// running tool.
		saveToolConfigurationToDisk();
		return true;
	}

	void saveToolConfigurationToDisk() {
		ToolTemplate template = saveToolToToolTemplate();
		Element root = new Element(FRONT_END_TOOL_XML_NAME);

		String version = Application.getApplicationVersion();
		root.setAttribute(VERSION_ATTRIBUTE_NAME, version);
		root.addContent(template.saveToXml());
		try (OutputStream os = new FileOutputStream(TOOL_FILE)) {
			org.jdom.Document doc = new org.jdom.Document(root);
			XMLOutputter xmlOut = new GenericXMLOutputter();
			xmlOut.output(doc, os);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error", "Error saving front end configuration", e);
		}
	}

	private void installFrontEndPlugins() {
		installFrontEndPlugin();

		// manually install for old tool versions that have no knowledge of utility plugins
		if (isPreUtilityGhidraVersion()) {
			installUtilityPlugins();
		}
	}

	private boolean isPreUtilityGhidraVersion() {

		Element root = getToolFileXml();
		if (root == null) {
			// not file from which to check the version; return true to allow client to perform
			// default initialization
			return true;
		}
		String version = root.getAttributeValue(VERSION_ATTRIBUTE_NAME);

		// Note: any version implies the tool is newer than the addition of the 'version'
		// attribute.  In that case, the utility plugins are managed by the xml.
		return StringUtils.isBlank(version);
	}

	/**
	 * Add those plugins that implement the ApplicationLevelPlugin interface and have a
	 * RELEASED status and not (example || testing) category.
	 */
	private void installDefaultApplicationLevelPlugins() {
		List<String> classNames = new ArrayList<>();
		for (Class<? extends Plugin> pluginClass : ClassSearcher.getClasses(Plugin.class,
			c -> ApplicationLevelPlugin.class.isAssignableFrom(c))) {

			PluginDescription pd = PluginDescription.getPluginDescription(pluginClass);
			String category = pd.getCategory();
			boolean isBadCategory = category.equals(GenericPluginCategoryNames.EXAMPLES) ||
				category.equals(GenericPluginCategoryNames.TESTING);
			if (pd.getStatus() == PluginStatus.RELEASED && !isBadCategory) {
				classNames.add(pluginClass.getName());
			}
		}

		try {
			addPlugins(classNames);
		}
		catch (PluginException e) {
			Msg.showError(this, getToolFrame(), "Plugin Error", "Error restoring front-end plugins",
				e);
		}
	}

	private void installFrontEndPlugin() {
		plugin = new FrontEndPlugin(this);
		plugin.setProjectManager(getProjectManager());
		try {
			addPlugin(plugin);
		}
		catch (PluginException e) {
			// should not happen
			Msg.showError(this, getToolFrame(), "Can't Create Project Window", e.getMessage(), e);
		}
		compProvider = plugin.getFrontEndProvider();

		showComponentHeader(compProvider, false);
	}

	/**
	 * Get the preferred default tool launch mode
	 * @return default tool launch mode
	 */
	public DefaultLaunchMode getDefaultLaunchMode() {
		return defaultLaunchMode;
	}

	private void initFrontEndOptions() {
		ToolOptions options = getOptions(ToolConstants.TOOL_OPTIONS);
		HelpLocation help =
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Front_End_Tool_Options");

		options.registerOption(DEFAULT_TOOL_LAUNCH_MODE, DefaultLaunchMode.DEFAULT, help,
			"Indicates if a new or already running tool should be used during default launch.");
		options.registerOption(AUTOMATICALLY_SAVE_TOOLS, true, help,
			"When enabled tools will be saved when they are closed");
		options.registerOption(USE_ALERT_ANIMATION_OPTION_NAME, true, help,
			"Signals that user notifications should be animated.  This makes notifications more " +
				"distinguishable.");
		options.registerOption(SHOW_TOOLTIPS_OPTION_NAME, true, help,
			"Controls the display of tooltip popup windows.");
		options.registerOption(ENABLE_COMPRESSED_DATABUFFER_OUTPUT, false, help,
			"When enabled data buffers sent to Ghidra Server are compressed (see server " +
				"configuration for other direction)");

		options.registerOption(RESTORE_PREVIOUS_PROJECT_NAME, true, help,
			"Restore the previous project when Ghidra starts.");

		defaultLaunchMode = options.getEnum(DEFAULT_TOOL_LAUNCH_MODE, defaultLaunchMode);

		boolean autoSave = options.getBoolean(AUTOMATICALLY_SAVE_TOOLS, true);
		GhidraTool.autoSave = autoSave;

		boolean animationEnabled = options.getBoolean(USE_ALERT_ANIMATION_OPTION_NAME, true);
		AnimationUtils.setAnimationEnabled(animationEnabled);

		boolean showToolTips = options.getBoolean(SHOW_TOOLTIPS_OPTION_NAME, true);
		DockingUtils.setTipWindowEnabled(showToolTips);

		boolean compressDataBuffers =
			options.getBoolean(ENABLE_COMPRESSED_DATABUFFER_OUTPUT, false);
		DataBuffer.enableCompressedSerializationOutput(compressDataBuffers);

		shouldRestorePreviousProject = options.getBoolean(RESTORE_PREVIOUS_PROJECT_NAME, true);

		options.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (DEFAULT_TOOL_LAUNCH_MODE.equals(optionName)) {
			defaultLaunchMode = (DefaultLaunchMode) newValue;
		}
		if (AUTOMATICALLY_SAVE_TOOLS.equals(optionName)) {
			GhidraTool.autoSave = (Boolean) newValue;
		}
		else if (USE_ALERT_ANIMATION_OPTION_NAME.equals(optionName)) {
			AnimationUtils.setAnimationEnabled((Boolean) newValue);
		}
		else if (SHOW_TOOLTIPS_OPTION_NAME.equals(optionName)) {
			DockingUtils.setTipWindowEnabled((Boolean) newValue);
		}
		else if (ENABLE_COMPRESSED_DATABUFFER_OUTPUT.equals(optionName)) {
			DataBuffer.enableCompressedSerializationOutput((Boolean) newValue);
		}
		else if (RESTORE_PREVIOUS_PROJECT_NAME.equals(optionName)) {
			shouldRestorePreviousProject = (Boolean) newValue;
		}
	}

	@Override
	public void exit() {
		plugin.exitGhidra();
	}

	@Override
	public void close() {
		close(true);
	}

	/**
	 * Set the active project.
	 *
	 * @param project may be null if there is no active project
	 */
	public void setActiveProject(Project project) {

		if (isDisposed) {
			return;
		}

		configureToolAction.setEnabled(true);
		setProject(project);
		AppInfo.setActiveProject(project);
		plugin.setActiveProject(project);
	}

	/**
	 * Checks to see if the previous project should be restored
	 *
	 * @return true if the previous project should be restored; otherwise, false
	 */
	public boolean shouldRestorePreviousProject() {
		return shouldRestorePreviousProject;
	}

	/**
	 * Add the given project listener.
	 *
	 * @param l listener to add
	 */
	public void addProjectListener(ProjectListener l) {
		listeners.add(l);
	}

	/**
	 * Remove the given project listener.
	 *
	 * @param l listener to remove
	 */
	public void removeProjectListener(ProjectListener l) {
		listeners.remove(l);
	}

	/**
	 * NOTE: do not call this from a non-Swing thread
	 *
	 * @param tool the tool
	 * @return true if the repository is null or is connected.
	 */
	boolean checkRepositoryConnected(PluginTool tool) {
		RepositoryAdapter repository = tool.getProject().getRepository();
		if (repository == null) {
			return true;
		}

		if (repository.verifyConnection()) {
			return true;
		}

		if (OptionDialog.showYesNoDialog(tool.getToolFrame(), "Lost Connection to Server",
			"The connection to the Ghidra Server has been lost.\n" +
				"Do you want to reconnect now?") == OptionDialog.OPTION_ONE) {
			try {
				repository.connect();
				return true;
			}
			catch (NotConnectedException e) {
				// message displayed by repository server adapter
				return false;
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Repository Connection",
					tool.getToolFrame());
				return false;
			}
		}

		return false;
	}

	/**
	 * Check in the given domain file.
	 *
	 * @param tool tool that has the domain file opened
	 * @param domainFile domain file to check in
	 */
	public void checkIn(PluginTool tool, DomainFile domainFile) {
		checkIn(tool, List.of(domainFile), tool.getToolFrame());
	}

	/**
	 * Check in the list of domain files.
	 *
	 * @param tool tool that has the domain files opened
	 * @param fileList list of DomainFile objects
	 * @param parent parent of dialog if an error occurs during checkin
	 */
	public void checkIn(PluginTool tool, List<DomainFile> fileList, Component parent) {

		if (!checkRepositoryConnected(tool)) {
			return;
		}

		ArrayList<DomainFile> changedList = new ArrayList<>();
		ArrayList<DomainFile> list = new ArrayList<>();
		for (DomainFile df : fileList) {
			if (df != null && df.canCheckin()) {
				if (!canCloseDomainFile(df)) {
					continue;
				}
				list.add(df);
				if (df.isChanged()) {
					changedList.add(df);
				}
			}
		}

		if (changedList.size() > 0) {
			ChangedFilesDialog dialog = new ChangedFilesDialog(tool, changedList);
			dialog.setCancelToolTipText("Cancel Check In");
			if (!dialog.showDialog()) {// blocks until the user hits Save or Cancel
				Msg.info(this, "Checkin canceled");
				return;
			}
			for (int i = 0; i < changedList.size(); i++) {
				DomainFile df = changedList.get(i);
				if (df.isChanged()) {
					list.remove(df);
				}
			}
		}
		if (list.size() > 0) {
			tool.execute(new CheckInTask(tool, list, parent));
		}
		else {
			Msg.showError(this, tool.getToolFrame(), "Checkin Failed", "Unable to checkin file(s)");
		}
	}

	/**
	 * Merge the latest version in the repository with the given checked out
	 * domain file. Upon completion of the merge, the domain file appears as
	 * though the latest version was checked out.
	 *
	 * @param tool tool that has the domain file opened
	 * @param domainFile domain file where latest version will be merged into
	 * @param taskListener listener that is notified when the merge task
	 *            completes
	 */
	public void merge(PluginTool tool, DomainFile domainFile, TaskListener taskListener) {
		ArrayList<DomainFile> list = new ArrayList<>();
		list.add(domainFile);
		merge(tool, list, taskListener);
	}

	/**
	 * Merge the latest version (in the repository) of each checked out file in
	 * fileList. Upon completion of the merge, the domain file appears as though
	 * the latest version was checked out.
	 *
	 * @param tool tool that has the domain files opened
	 * @param fileList list of files that are checked out and are to be merged
	 * @param taskListener listener that is notified when the merge task
	 *            completes
	 */
	public void merge(PluginTool tool, List<DomainFile> fileList, TaskListener taskListener) {

		if (!checkRepositoryConnected(tool)) {
			return;
		}

		ArrayList<DomainFile> list = new ArrayList<>();
		ArrayList<DomainFile> changedList = new ArrayList<>();
		for (DomainFile df : fileList) {
			if (df != null && df.canMerge()) {
				if (!canCloseDomainFile(df)) {
					continue;
				}
				list.add(df);
				if (df.isChanged()) {
					changedList.add(df);
				}
			}
		}
		if (changedList.size() > 0) {
			ChangedFilesDialog dialog = new ChangedFilesDialog(tool, changedList);
			dialog.setCancelToolTipText("Cancel Merge");
			if (!dialog.showDialog()) {// blocks until the user hits Save or Cancel
				Msg.info(this, "Merge canceled");
				return;
			}
			for (int i = 0; i < changedList.size(); i++) {
				DomainFile df = changedList.get(i);
				if (df.isChanged()) {
					list.remove(df);
				}
			}
		}
		if (list.size() > 0) {
			execute(new MergeTask(tool, list, taskListener));
		}
		else {
			Msg.showError(this, tool.getToolFrame(), "Update Failed", "Unable to update file(s)");
		}

	}

	@Override
	public void setVisible(boolean visibility) {
		if (visibility) {
			super.setVisible(visibility);
			plugin.rebuildRecentMenus();
			checkWhatsNewPreference();
		}
		else {
			super.setVisible(visibility);

			// Treat setVisible(false) as a dispose, as this is the only time we should be hidden
			AppInfo.setFrontEndTool(null);
			AppInfo.setActiveProject(null);
			dispose();
		}
	}

	public void setBusy(boolean busy) {
		JFrame rootFrame = winMgr.getRootFrame();
		Component glassPane = rootFrame.getGlassPane();
		if (!(glassPane instanceof GGlassPane)) {
			Msg.debug(this, "Found root frame without a GhidraGlassPane registered!");
			return;
		}
		GGlassPane dockingGlassPane = (GGlassPane) glassPane;
		dockingGlassPane.setBusy(busy);
	}

	private void addManageExtensionsAction() {

		DockingAction installExtensionsAction = new DockingAction("Extensions", "Project Window") {
			@Override
			public void actionPerformed(ActionContext context) {
				showExtensions();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isConfigurable();
			}
		};
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Install Extensions..." }, null,
				CONFIGURE_GROUP);
		menuData.setMenuSubGroup(CONFIGURE_GROUP + 2);
		installExtensionsAction.setMenuBarData(menuData);

		installExtensionsAction
				.setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "Extensions"));
		installExtensionsAction.setEnabled(true);
		addAction(installExtensionsAction);
	}

	private void addManagePluginsAction() {

		configureToolAction = new DockingAction("Configure Tool", "Project Window") {
			@Override
			public void actionPerformed(ActionContext context) {
				showConfig(false, false);
				manageDialog.setHelpLocation(
					new HelpLocation(GenericHelpTopics.FRONT_END, "Configure"));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isConfigurable();
			}
		};

		MenuData menuData = new MenuData(new String[] { ToolConstants.MENU_FILE, "Configure..." },
			null, CONFIGURE_GROUP);
		menuData.setMenuSubGroup(CONFIGURE_GROUP + 1);
		configureToolAction.setMenuBarData(menuData);

		configureToolAction
				.setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "Configure"));
		configureToolAction.setEnabled(true);
		addAction(configureToolAction);
	}

	@Override
	public ToolTemplate getToolTemplate(boolean includeConfigState) {
		ToolTemplate toolTemplate = new FrontEndToolTemplate(getIconURL(),
			saveToXml(includeConfigState), getSupportedDataTypes());
		return toolTemplate;
	}

	/**
	 * Get project listeners.
	 *
	 * @return ProjectListener[]
	 */
	Iterable<ProjectListener> getListeners() {
		return listeners;
	}

	// access for Junit tests
	ComponentProvider getProvider() {
		return compProvider;
	}

	SaveState getSaveableDisplayData() {
		SaveState saveState = new SaveState();
		plugin.writeDataState(saveState);
		return saveState;
	}

	void setSaveableDisplayData(SaveState saveState) {
		plugin.readDataState(saveState);
	}

	/**
	 * Refresh the plugins in the Ghidra Project Window based on what is contained in the given XML
	 * Element.
	 *
	 * @param tc object that contains an entry for each plugin and its configuration state
	 */
	private void refresh(ToolTemplate tc) {
		listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();
		Element root = tc.saveToXml();
		Element elem = root.getChild("TOOL");

		restoreOptionsFromXml(elem);
		try {
			restorePluginsFromXml(elem);
		}
		catch (PluginException e) {
			Msg.showError(this, getToolFrame(), "Error Restoring Front-end Plugins", e.getMessage(),
				e);
		}
		winMgr.restoreFromXML(tc.getToolElement());

		setConfigChanged(false);
	}

	private void createActions() {
		addExitAction();
		addManagePluginsAction();
		addManageExtensionsAction();
		addOptionsAction();
		addHelpActions();

		// our log file action
		DockingAction action = new DockingAction("Show Log", ToolConstants.TOOL_OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				showGhidraUserLogFile();
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_HELP, "Show Log" }, null, "BBB"));

		action.setEnabled(true);
		addAction(action);
	}

	private void setDividerLocation() {
		String dividerLocStr = Preferences.getProperty(GHIDRA_MAIN_PANEL_DIVIDER_LOC);
		if (dividerLocStr != null) {
			int dividerLoc = parse(dividerLocStr, -1);
			ProjectDataPanel pdp = plugin.getProjectDataPanel();
			pdp.setDividerLocation(dividerLoc);
			pdp.invalidate();
			getToolFrame().validate();
		}
	}

	/**
	 * Get the int value for the given string.
	 *
	 * @param value the string value to parse
	 * @param defaultValue return this value if a NumberFormatException is
	 *            thrown during the parseInt() method
	 */
	private int parse(String value, int defaultValue) {
		if (value != null) {
			try {
				return Integer.parseInt(value);
			}
			catch (NumberFormatException e) {
				// don't care
			}
		}
		return defaultValue;
	}

	/**
	 * Check the "What's New" preference; if it has not been set, then show the
	 * "What's New" help page. This should only happen if the preference was
	 * never set.
	 */
	private void checkWhatsNewPreference() {

		if (SystemUtilities.isInDevelopmentMode() || SystemUtilities.isInTestingMode()) {
			return; // don't show help for dev mode
		}

		HelpService help = Help.getHelpService();

		// if this is the first time Ghidra is being run, pop up
		// the What's New help page
		String showWhatsNewStribng = Preferences.getProperty(GHIDRA_SHOW_WHATS_NEW, "true");
		boolean showWhatsNew = Boolean.parseBoolean(showWhatsNewStribng);
		if (!showWhatsNew) {
			return;
		}

		Preferences.setProperty(GHIDRA_SHOW_WHATS_NEW, "false");
		Preferences.store();

		ResourceFile installDir = Application.getInstallationDirectory();
		ResourceFile whatsNewFile = new ResourceFile(installDir, "docs/WhatsNew.html");
		try {
			URL url = whatsNewFile.toURL();
			help.showHelp(url);
		}
		catch (MalformedURLException e) {
			Msg.debug(this, "Unable to show the What's New help page", e);
		}
	}

	@Override
	public boolean canCloseDomainFile(DomainFile df) {
		PluginTool[] tools = getProject().getToolManager().getRunningTools();
		for (PluginTool tool : tools) {
			DomainFile[] files = tool.getDomainFiles();
			for (DomainFile domainFile : files) {
				if (df == domainFile) {
					return tool.canCloseDomainFile(df);
				}
			}
		}
		return true;
	}

	void showGhidraUserLogFile() {
		File logFile = LoggingInitialization.getApplicationLogFile();
		if (logFile == null) {
			return;// something odd is going on; can't find log file
		}

		if (logProvider == null) {
			logProvider = new LogComponentProvider(this, logFile);
			showDialog(logProvider);
			return;
		}

		if (logProvider.isShowing()) {
			logProvider.toFront();
		}
		else {
			showDialog(logProvider, getToolFrame());
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class LogComponentProvider extends ReusableDialogComponentProvider {

		private final File logFile;
		private Dimension defaultSize = new Dimension(600, 400);

		private FileWatcher watcher;

		LogComponentProvider(PluginTool tool, File logFile) {
			super("Ghidra User Log", false, false, false, false);

			this.logFile = logFile;

			addWorkPanel(buildWorkPanel());
		}

		/**
		 * Need to override this method so we can stop the file watcher when the
		 * dialog is closed.
		 */
		@Override
		protected void dialogClosed() {
			if (watcher != null) {
				watcher.stop();
			}
		}

		/**
		 * Need to override this method so we can stop the file watcher when the
		 * dialog is closed.
		 */
		@Override
		protected void dialogShown() {
			if (watcher != null) {
				watcher.start();
			}
		}

		private JPanel buildWorkPanel() {

			JPanel panel = new JPanel(new BorderLayout()) {
				@Override
				public Dimension getPreferredSize() {
					return defaultSize;
				}
			};

			try {
				FVEventListener eventListener = new FVEventListener();

				ChunkModel model = new ChunkModel();
				ChunkReader reader = new ChunkReader(logFile, model);
				FileViewer viewer = new FileViewer(reader, model, eventListener);
				panel.add(viewer);
				panel.setVisible(true);

				// Turn on the file watcher so events will be fired off whenever the log file
				// changes.
				watcher = new FileWatcher(logFile, eventListener);
				watcher.start();

				// Now tell subscribers that the file needs to be read-in. Have it view the bottom
				// of the file on startup.
				FVEvent loadEvt = new FVEvent(EventType.SCROLL_END, null);
				eventListener.send(loadEvt);
			}
			catch (IOException e) {
				Msg.error(this, "Exception reading log file", e);
			}

			return panel;
		}
	}

	/**
	 * Task to merge latest version of a domain file into the checked out
	 * version.
	 */
	private class MergeTask extends Task {
		private List<DomainFile> list;
		private PluginTool tool;
		private TaskListener taskListener;
		private boolean wasCanceled;

		/**
		 * Construct a new MergeTask.
		 *
		 * @param tool tool that has the domain files open
		 * @param list list of DomainFiles to be merged
		 * @param taskListener listener that is notified when this task
		 *            completes
		 */
		MergeTask(PluginTool tool, List<DomainFile> list, TaskListener taskListener) {
			super("Merge", true, true, true);
			this.tool = tool;
			this.list = list;
			this.taskListener = taskListener;
		}

		@Override
		public void run(TaskMonitor monitor) {

			String currentName = null;
			try {
				for (int i = 0; i < list.size() && !monitor.isCancelled(); i++) {

					DomainFile df = list.get(i);
					currentName = df.getName();
					monitor.setMessage("Initiating Merging for " + currentName);

					df.merge(true, monitor);
				}
			}
			catch (VersionException e) {
				Msg.showError(this, tool.getToolFrame(), "Error During Merge Process",
					"Versioned file was created with newer version of Ghidra: " + currentName);
			}
			catch (CancelledException e) {
				wasCanceled = true;
				Msg.info(this, "Merge Process was canceled");
			}
			catch (IOException e) {
				ClientUtil.handleException(getProject().getRepository(), e, "Merge Process",
					tool.getToolFrame());
			}
			notifyTaskListener();
		}

		private void notifyTaskListener() {

			if (taskListener == null) {
				return;
			}

			Swing.runNow(() -> {
				if (wasCanceled) {
					taskListener.taskCancelled(MergeTask.this);
				}
				else {
					taskListener.taskCompleted(MergeTask.this);
				}
			});
		}

	}

	private static class FrontEndToolTemplate extends GhidraToolTemplate {
		FrontEndToolTemplate(ToolIconURL iconURL, Element element, Class<?>[] supportedDataTypes) {
			super(iconURL, element, supportedDataTypes);
		}
	}

}
