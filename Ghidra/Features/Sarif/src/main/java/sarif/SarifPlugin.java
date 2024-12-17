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
package sarif;

import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.Icon;

import com.contrastsecurity.sarif.SarifSchema210;
import com.google.gson.JsonSyntaxException;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GIcon;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import sarif.io.SarifGsonIO;
import sarif.io.SarifIO;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Sarif Plugin.",
	description = "SARIF parsing and visualization plugin.",
	servicesProvided = { SarifService.class }
)
//@formatter:on

/**
 * A {@link ProgramPlugin} for reading in sarif files
 */
public class SarifPlugin extends ProgramPlugin implements SarifService, OptionsChangeListener {
	public static final String NAME = "Sarif";
	public static final Icon SARIF_ICON = new GIcon("icon.plugin.bookmark.type.note");

	private Map<Program, SarifController> sarifControllers;
	private SarifIO io;

	public SarifPlugin(PluginTool tool) {
		super(tool);
		this.sarifControllers = new HashMap<>();
		this.io = new SarifGsonIO();
	}

	@Override
	protected void init() {
		createActions();
		initializeOptions();
	}

	public void readFile(File file) {
		if (file != null) {
			try {
				showSarif(file.getName(), io.readSarif(file));
			}
			catch (JsonSyntaxException | IOException e) {
				Msg.showError(this, tool.getActiveWindow(), "File parse error",
					"Invalid Sarif File");
			}
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		Program eventProgram = null;
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			eventProgram = ev.getActiveProgram();
		}
		else if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent ev = (ProgramOpenedPluginEvent) event;
			eventProgram = ev.getProgram();
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			eventProgram = ev.getProgram();
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent ev = (ProgramClosedPluginEvent) event;
			eventProgram = ev.getProgram();
		}
		else if (event instanceof ProgramVisibilityChangePluginEvent) {
			ProgramVisibilityChangePluginEvent ev = (ProgramVisibilityChangePluginEvent) event;
			eventProgram = ev.getProgram();
		}
		SarifController controller = sarifControllers.get(eventProgram);
		if (controller != null) {
			if (event instanceof ProgramClosedPluginEvent) {
				controller.dispose();
				sarifControllers.remove(eventProgram, controller);
			}
			else if (event instanceof ProgramVisibilityChangePluginEvent) {
				ProgramVisibilityChangePluginEvent ev = (ProgramVisibilityChangePluginEvent) event;
				controller.showTable(ev.isProgramVisible());
			}
			else {
				controller.showTable(true);
			}
		}
	}

	@Override
	public SarifSchema210 readSarif(File sarifFile) throws JsonSyntaxException, IOException {
		return io.readSarif(sarifFile);
	}

	@Override
	public SarifSchema210 readSarif(String sarif) throws JsonSyntaxException, IOException {
		return io.readSarif(sarif);
	}

	public SarifController getController() {
		currentProgram = getCurrentProgram();
		if (currentProgram != null) {
			if (!sarifControllers.containsKey(currentProgram)) {
				SarifController controller = new SarifController(currentProgram, this);
				sarifControllers.put(currentProgram, controller);
			}
			return sarifControllers.get(currentProgram);
		}
		Msg.showError(this, tool.getActiveWindow(), "File parse error", "No current program");
		return null;
	}

	/**
	 * Ultimately both selections end up calling this to actually show something on
	 * the Ghidra gui
	 *
	 * @param logName
	 * @param sarif
	 */
	public void showSarif(String logName, SarifSchema210 sarif) {
		SarifController currentController = getController();
		if (currentController != null) {
			if (sarif != null) {
				currentController.showTable(logName, sarif);
			}
			else {
				Msg.showError(this, tool.getActiveWindow(), "File parse error",
					"No SARIF generated - check directories");
			}
			return;
		}
		Msg.showError(this, tool.getActiveWindow(), "File parse error", "No current program");
	}

	public void makeSelection(List<Address> addrs) {
		AddressSet selection = new AddressSet();
		for (Address addr : addrs) {
			selection.add(addr);
		}
		this.setSelection(selection);
	}

	private void createActions() {
		//@formatter:off
		new ActionBuilder("Read", getName())
			.menuPath("Tools", "Sarif", "Read File")
			.menuGroup("sarif", "1")
			.helpLocation(new HelpLocation("Sarif", "Using_SARIF_Files"))
			.enabledWhen(ctx -> getCurrentProgram() != null)
			.onAction(e -> {
				GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
				this.readFile(chooser.getSelectedFile());
			})
			.buildAndInstall(tool);
		//@formatter:on
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);
		options.addOptionsChangeListener(this);

		HelpLocation help = new HelpLocation(getName(), "Options");

		Options sarifOptions = options.getOptions(NAME);
		registerOptions(sarifOptions, help);
		loadOptions(sarifOptions);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue)
			throws OptionsVetoException {

		Options sarifOptions = options.getOptions(NAME);
		loadOptions(sarifOptions);
	}

	public void registerOptions(Options options, HelpLocation help) {

		options.setOptionsHelpLocation(help);

		options.registerOption("Display Artifacts", displayArtifacts(), help,
			"Display artifacts by default");

		options.registerOption("Display Graphs", displayGraphs(), help,
			"Display graphs by default");

		options.registerOption("Max Graph Size", getGraphSize(), help,
			"Maximum number of nodes per graph");

		options.registerOption("Append Graphs", appendToGraph(), help, "Append to existing graph");

	}

	public void loadOptions(Options options) {

		displayArtifactsByDefault = options.getBoolean("Display Artifacts", displayArtifacts());
		displayGraphsByDefault = options.getBoolean("Display Graphs", displayGraphs());
		maxGraphSize = options.getInt("Max Graph Size", getGraphSize());
		appendToCurrentGraph = options.getBoolean("Append Graphs", appendToGraph());

	}

	private boolean displayGraphsByDefault = false;

	public boolean displayGraphs() {
		return displayGraphsByDefault;
	}

	private boolean displayArtifactsByDefault = false;

	public boolean displayArtifacts() {
		return displayArtifactsByDefault;
	}

	private int maxGraphSize = 1000;

	public int getGraphSize() {
		return maxGraphSize;
	}

	private boolean appendToCurrentGraph = false;

	public boolean appendToGraph() {
		return appendToCurrentGraph;
	}

}
