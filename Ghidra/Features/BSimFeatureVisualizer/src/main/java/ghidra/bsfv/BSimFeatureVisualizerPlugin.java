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
package ghidra.bsfv;

import java.io.IOException;

import org.xml.sax.SAXException;

import docking.action.builder.ActionBuilder;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.features.bsim.query.BsimPluginPackage;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = BsimPluginPackage.NAME,
	category = "BSim",
	shortDescription = "BSim Feature Visualizer",
	description = "Displays BSim features as graphs and highlighted regions in the decompiler.",
	servicesRequired = { GoToService.class, GraphDisplayBroker.class,
		DecompilerHighlightService.class},
	eventsProduced = { ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class }
)
//@formatter:on

/**
 * A plugin for visualizing BSim features as graphs and highlights in the decompiler.
 */
public class BSimFeatureVisualizerPlugin extends ProgramPlugin
		implements DomainObjectListener, OptionsChangeListener {

	private BsfvTableProvider provider;
	private Function currentFunction;

	//options
	public static final String BSIM_FEATURE_VISUALIZER_OPTION_NAME = "BsimFeatureVisualizer";
	public static final String DB_CONFIG_FILE = "Database Configuration File";
	public static final String REUSE_GRAPH = "Reuse Graph";
	public static final String DECOMPILER_TIMEOUT = "Decompiler Timeout";
	public static final String HIGHLIGHT_BY_ROW = "Highlight by Row";
	public static final String BSIM_FEATURE_VISUALIZER_ACTION = "Show BSim Feature Visualizer";
	private String dbConfigFile = "medium_nosize.xml";
	private boolean reuseGraph = true;
	private boolean highlightByRow = true;
	private int decompilerTimeout = 10;
	private DecompilerHighlightService highlightService;

	/**
	 * Creates a BSimFeatureVisualizerPlugin for the given {@link PluginTool}
	 * @param tool plugin tool
	 */
	public BSimFeatureVisualizerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		initOptions(tool.getOptions(BSIM_FEATURE_VISUALIZER_OPTION_NAME));
		highlightService = getTool().getService(DecompilerHighlightService.class);

		new ActionBuilder(BSIM_FEATURE_VISUALIZER_ACTION, getName())
				.menuPath("BSim", "BSim Feature Visualizer")
				.helpLocation(new HelpLocation(getName(), getName()))
				.onAction(c -> {
					if (currentLocation != null) {
						FunctionManager functionManager = currentProgram.getFunctionManager();
						currentFunction =
							functionManager.getFunctionContaining(currentLocation.getAddress());
					}
					provider = new BsfvTableProvider(this);
				})
				.buildAndInstall(tool);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		switch (optionName) {
			case DB_CONFIG_FILE:
				dbConfigFile = (String) newValue;
				if (provider != null) {
					provider.reload();
				}
				break;
			case REUSE_GRAPH:
				reuseGraph = (Boolean) newValue;
				break;
			case DECOMPILER_TIMEOUT:
				decompilerTimeout = (Integer) newValue;
				if (provider != null) {
					provider.reload();
				}
				break;
			case HIGHLIGHT_BY_ROW:
				highlightByRow = (Boolean) newValue;
				break;
			default:
				Msg.error(this, "Unrecognized option: " + optionName);
				break;
		}
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (provider == null) {
			return;
		}

		if (location == null) {
			return;
		}
		if (currentFunction != null && currentFunction.getBody().contains(location.getAddress())) {
			return;
		}
		FunctionManager functionManager = currentProgram.getFunctionManager();
		currentFunction = functionManager.getFunctionContaining(location.getAddress());
		if (currentFunction == null) {
			return;
		}
		provider.reload();
	}

	@Override
	protected void programActivated(Program program) {
		if (provider == null) {
			return;
		}
		program.addListener(this);
		if (currentLocation != null) {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			currentFunction = functionManager.getFunctionContaining(currentLocation.getAddress());
		}
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		currentFunction = null;
		program.removeListener(this);
		if (provider != null) {
			provider.programDeactivated();
		}
	}

	/**
	 * Returns the function whose features are in displayed in the table
	 * @return current function
	 */
	Function getFunction() {
		return currentFunction;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		//Following {@link DecompilerProvider}'s lead, reload on any change to the program
		//note that BSimFeatureTableProvider.reload() checks for visibility
		if (provider != null) {
			provider.reload();
		}
	}

	@Override
	public void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		if (provider != null) {
			provider.dispose();
		}
		super.dispose();
	}

	/**
	 * Parses the signature settings from the database configuration file specified in the options
	 * for this plugin.
	 * @return signature settings
	 */
	int getSignatureSettings() {
		ResourceFile dbConfigurationFile = Application.findDataFileInAnyModule(dbConfigFile);
		if (dbConfigurationFile == null) {
			Msg.showError(this, null, "File not found", "Couldn't find file " + dbConfigFile);
			return 0;
		}
		Configuration dbConfig = new Configuration();

		try {
			//load template appends ".xml" so strip it off here
			dbConfig.loadTemplate(dbConfigurationFile.getParentFile(),
				dbConfigFile.substring(0, dbConfigFile.length() - 4));
		}
		catch (SAXException | IOException e) {
			Msg.showError(dbConfig, null, "Problem with configuration file " + dbConfigFile,
				e.getMessage());
		}
		return dbConfig.info.settings;
	}

	/**
	 * Returns a boolean determining whether the plugin should reuse the graph when
	 * drawing feature graphs.
	 * @return reuseGraph
	 */
	public boolean getReuseGraph() {
		return reuseGraph;
	}

	/**
	 * Returns the decompiler timeout setting.
	 * @return decompiler timeout
	 */
	public int getDecompilerTimeout() {
		return decompilerTimeout;
	}

	/**
	 * Returns a boolean indicating whether the plugin should automatically apply decompiler
	 * highlights when the selected row changes.
	 * @return highlight by row
	 */
	public boolean getHighlightByRow() {
		return highlightByRow;
	}

	/**
	 * Returns the {@link DecompilerHighlightService} for this plugin.
	 * @return decompiler highlight service
	 */
	DecompilerHighlightService getDecompilerHighlightService() {
		return highlightService;
	}

	private void initOptions(ToolOptions options) {
		options.registerOption(DB_CONFIG_FILE, dbConfigFile,
			new HelpLocation(this.getName(), "Config_File"),
			"Database configuration file to read signature settings from.");
		dbConfigFile = options.getString(DB_CONFIG_FILE, dbConfigFile);
		options.registerOption(REUSE_GRAPH, reuseGraph,
			new HelpLocation(this.getName(), "Reuse_Graph"),
			"Clear and re-use the graph window or create new graph window when graphing features.");
		reuseGraph = options.getBoolean(REUSE_GRAPH, reuseGraph);
		options.registerOption(DECOMPILER_TIMEOUT, decompilerTimeout,
			new HelpLocation(this.getName(), "Decompiler_Timeout"), "Decompiler Timeout (seconds)");
		decompilerTimeout = options.getInt(DECOMPILER_TIMEOUT, decompilerTimeout);
		options.registerOption(HIGHLIGHT_BY_ROW, highlightByRow,
			new HelpLocation(this.getName(), "Highlight_By_Row"),
			"Highlight feature in decompiler whenever selected row changes");
		highlightByRow = options.getBoolean(HIGHLIGHT_BY_ROW, highlightByRow);
		options.addOptionsChangeListener(this);
	}

}
