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
package ghidra.app.plugin.core.functiongraph;

import java.util.*;

import javax.swing.ImageIcon;

import org.jdom.Element;

import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutOptions;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.app.services.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = FunctionGraphPlugin.FUNCTION_GRAPH_NAME,
	description = "Plugin for show a graphical representation of the code blocks of a function",
	servicesRequired = { GoToService.class, BlockModelService.class, CodeViewerService.class, ProgramManager.class }
)
//@formatter:on
public class FunctionGraphPlugin extends ProgramPlugin implements OptionsChangeListener {
	static final String FUNCTION_GRAPH_NAME = "Function Graph";
	static final String PLUGIN_OPTIONS_NAME = FUNCTION_GRAPH_NAME;

	static final ImageIcon ICON = ResourceManager.loadImage("images/function_graph.png");

	public static final ImageIcon GROUP_ICON =
		ResourceManager.loadImage("images/shape_handles.png");
	public static final ImageIcon GROUP_ADD_ICON =
		ResourceManager.loadImage("images/shape_square_add.png");
	public static final ImageIcon UNGROUP_ICON =
		ResourceManager.loadImage("images/shape_ungroup.png");

	private static final String USER_DEFINED_FORMAT_CONFIG_NAME = "USER_DEFINED_FORMAT_MANAGER";

	private static final String PROVIDER_ID = "Provider";
	private static final String PROGRAM_PATH_ID = "Program Path";
	private static final String DISCONNECTED_COUNT_ID = "Disconnected Count";

	private FGProvider connectedProvider;
	private List<FGProvider> disconnectedProviders = new ArrayList<>();
	private FormatManager userDefinedFormatManager;

	private FunctionGraphOptions functionGraphOptions = new FunctionGraphOptions();

	private FGColorProvider colorProvider;
	private List<FGLayoutProvider> layoutProviders;

	public FunctionGraphPlugin(PluginTool tool) {
		super(tool, true, true, true);

		colorProvider = new IndependentColorProvider(tool);
	}

	@Override
	protected void init() {
		super.init();

		layoutProviders = loadLayoutProviders();

		createNewProvider();
		initializeOptions();

		ColorizingService colorizingService = tool.getService(ColorizingService.class);
		if (colorizingService != null) {
			colorProvider = new ToolBasedColorProvider(this, colorizingService);
		}
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ClipboardService.class) {
			connectedProvider.setClipboardService((ClipboardService) service);
			for (FGProvider disconnectedProvider : disconnectedProviders) {
				disconnectedProvider.setClipboardService((ClipboardService) service);
			}
		}
		else if (interfaceClass == ColorizingService.class) {
			colorProvider = new ToolBasedColorProvider(this, (ColorizingService) service);
			connectedProvider.refreshAndKeepPerspective();
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ClipboardService.class) {
			connectedProvider.setClipboardService((ClipboardService) service);
			for (FGProvider disconnectedProvider : disconnectedProviders) {
				disconnectedProvider.setClipboardService((ClipboardService) service);
			}
		}
		else if (interfaceClass == ColorizingService.class) {
			colorProvider = new IndependentColorProvider(tool);
			connectedProvider.refreshAndKeepPerspective();
		}
	}

	private List<FGLayoutProvider> loadLayoutProviders() {

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
		ToolOptions options = tool.getOptions(PLUGIN_OPTIONS_NAME);
		options.addOptionsChangeListener(this);
		functionGraphOptions.registerOptions(options);
		functionGraphOptions.loadOptions(options);

		for (FGLayoutProvider layoutProvider : layoutProviders) {
			String layoutName = layoutProvider.getLayoutName();
			Options layoutToolOptions = options.getOptions(layoutName);
			FGLayoutOptions layoutOptions = layoutProvider.createLayoutOptions(layoutToolOptions);
			if (layoutOptions == null) {
				continue; // many layouts do not have options
			}

			layoutOptions.registerOptions(layoutToolOptions);
			layoutOptions.loadOptions(layoutToolOptions);
			functionGraphOptions.setLayoutOptions(layoutName, layoutOptions);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		functionGraphOptions.loadOptions(options);

		connectedProvider.optionsChanged();

		if (functionGraphOptions.optionChangeRequiresRelayout(optionName)) {
			connectedProvider.refreshAndKeepPerspective();
		}
		else if (VisualGraphOptions.VIEW_RESTORE_OPTIONS_KEY.equals(optionName)) {
			connectedProvider.clearViewSettings();
		}
		else {
			connectedProvider.refreshDisplayWithoutRebuilding();
		}

		connectedProvider.getComponent().repaint();
		for (FGProvider provider : disconnectedProviders) {
			provider.optionsChanged();
			provider.getComponent().repaint();
		}
	}

	@Override
	protected void programActivated(Program program) {
		if (connectedProvider == null) {
			return;
		}
		connectedProvider.doSetProgram(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		if (connectedProvider == null) {
			return;
		}
		connectedProvider.doSetProgram(null);
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (connectedProvider == null) {
			return;
		}
		connectedProvider.setLocation(location);
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		if (connectedProvider == null) {
			return;
		}
		connectedProvider.setSelection(selection);
	}

	@Override
	protected void highlightChanged(ProgramSelection highlight) {
		if (connectedProvider == null) {
			return;
		}
		connectedProvider.setHighlight(highlight);
	}

	@Override
	protected void programClosed(Program program) {
		if (currentProgram == program) {
			currentProgram = null;
		}

		connectedProvider.programClosed(program);

		Iterator<FGProvider> iterator = disconnectedProviders.iterator();
		while (iterator.hasNext()) {
			FGProvider provider = iterator.next();
			if (provider.getProgram() == program) {
				iterator.remove();
				removeProvider(provider);
			}
		}
	}

	void showProvider() {
		connectedProvider.setVisible(true);
		connectedProvider.setLocation(currentLocation);
	}

	void closeProvider(FGProvider provider) {
		if (provider == connectedProvider) {
			tool.showComponentProvider(provider, false);
		}
		else {
			disconnectedProviders.remove(provider);
			removeProvider(provider);
		}
	}

	private void createNewProvider() {
		connectedProvider = new FGProvider(this, true);
		connectedProvider.doSetProgram(currentProgram);
		connectedProvider.setLocation(currentLocation);
		connectedProvider.setSelection(currentSelection);
	}

	FGProvider createNewDisconnectedProvider() {
		FGProvider provider = new FGProvider(this, false);
		disconnectedProviders.add(provider);
		tool.showComponentProvider(provider, true);
		return provider;
	}

	@Override
	protected void dispose() {
		super.dispose();
		currentProgram = null;

		removeProvider(connectedProvider);
		for (FGProvider provider : disconnectedProviders) {
			removeProvider(provider);
		}
		disconnectedProviders.clear();
	}

	private void removeProvider(FGProvider provider) {
		if (provider == null) {
			return;
		}
		provider.dispose();
		tool.removeComponentProvider(provider);
	}

	public void handleProviderLocationChanged(FGProvider provider, ProgramLocation location) {
		if (provider != connectedProvider) {
			return;
		}
		firePluginEvent(new ProgramLocationPluginEvent(getName(), location, location.getProgram()));
	}

	public void handleProviderSelectionChanged(FGProvider provider, ProgramSelection selection) {
		if (provider != connectedProvider) {
			return;
		}

		if (selection == null) {
			return;
		}

		firePluginEvent(
			new ProgramSelectionPluginEvent(getName(), selection, provider.getProgram()));
	}

	public void handleProviderHighlightChanged(FGProvider provider, ProgramSelection highlight) {
		if (provider != connectedProvider) {
			return;
		}
		if (highlight == null) {
			return;
		}
		firePluginEvent(
			new ProgramHighlightPluginEvent(getName(), highlight, provider.getProgram()));
	}

	public void setUserDefinedFormat(FormatManager formatManager) {
		userDefinedFormatManager = formatManager;
		tool.setConfigChanged(true);
	}

	public FormatManager getUserDefinedFormat() {
		return userDefinedFormatManager;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		Element formatElement = saveState.getXmlElement(USER_DEFINED_FORMAT_CONFIG_NAME);
		if (formatElement != null) {
			OptionsService options = getTool().getService(OptionsService.class);
			ToolOptions displayOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
			ToolOptions fieldOptions = options.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			userDefinedFormatManager = new FormatManager(displayOptions, fieldOptions);
			SaveState formatState = new SaveState(formatElement);
			userDefinedFormatManager.readState(formatState);

			connectedProvider.formatChanged();
		}

		colorProvider.savePluginColors(saveState);
		connectedProvider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (userDefinedFormatManager != null) {
			SaveState formatState = new SaveState();
			userDefinedFormatManager.saveState(formatState);
			Element element = formatState.saveToXml();
			saveState.putXmlElement(USER_DEFINED_FORMAT_CONFIG_NAME, element);
		}

		colorProvider.loadPluginColor(saveState);

		if (connectedProvider != null) {
			connectedProvider.writeConfigState(saveState);
		}
	}

	@Override
	public void writeDataState(SaveState saveState) {
		if (connectedProvider != null) {
			connectedProvider.writeDataState(saveState);
			connectedProvider.writeConfigState(saveState);
		}
		saveState.putInt(DISCONNECTED_COUNT_ID, disconnectedProviders.size());
		int i = 0;
		for (FGProvider provider : disconnectedProviders) {
			SaveState providerSaveState = new SaveState();
			DomainFile df = provider.getProgram().getDomainFile();
			if (df.getParent() == null) {
				continue; // not contained within project
			}
			String programPathname = df.getPathname();
			providerSaveState.putString(PROGRAM_PATH_ID, programPathname);
			provider.writeDataState(providerSaveState);
			provider.writeConfigState(providerSaveState);
			String disconnectedName = PROVIDER_ID + i;
			saveState.putXmlElement(disconnectedName, providerSaveState.saveToXml());
			i++;
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		ProgramManager programManagerService = tool.getService(ProgramManager.class);

		if (connectedProvider != null) {
			connectedProvider.readDataState(saveState);
			connectedProvider.readConfigState(saveState);
		}
		int numDisconnected = saveState.getInt(DISCONNECTED_COUNT_ID, 0);
		for (int i = 0; i < numDisconnected; i++) {
			String disconnectedName = PROVIDER_ID + i;
			Element xmlElement = saveState.getXmlElement(disconnectedName);
			SaveState providerSaveState = new SaveState(xmlElement);
			String programPath = providerSaveState.getString(PROGRAM_PATH_ID, "");
			DomainFile file = tool.getProject().getProjectData().getFile(programPath);
			if (file == null) {
				continue;
			}
			Program program = programManagerService.openProgram(file);
			if (program != null) {
				FGProvider provider = createNewDisconnectedProvider();
				provider.doSetProgram(program);
				provider.readDataState(providerSaveState);
				provider.readConfigState(providerSaveState);
			}
		}
	}

	public FGColorProvider getColorProvider() {
		return colorProvider;
	}

	public FunctionGraphOptions getFunctionGraphOptions() {
		return functionGraphOptions;
	}

	public List<FGLayoutProvider> getLayoutProviders() {
		return Collections.unmodifiableList(layoutProviders);
	}
}
