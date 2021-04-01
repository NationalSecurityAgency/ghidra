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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WindowsResourceReferenceAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "WindowsResourceReference";
	private static final String DESCRIPTION =
		"Given certain Key windows API calls, tries to create references at the use of windows Resources.";

	boolean scriptWasFound = false;

	private final static String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";

	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"Select this check box if you want this analyzer to create analysis bookmarks when items of interest are created/identified by the analyzer.";

	private final static boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	public WindowsResourceReferenceAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		if (format.equals(PeLoader.PE_NAME)) {
			return true;
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return runScript(program, set, "WindowsResourceReference.java", monitor);
	}

	public boolean runScript(Program program, AddressSetView set, String scriptName,
			TaskMonitor monitor) {

		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);

		PluginTool tool = analysisManager.getAnalysisTool();
		Project project = findProject(tool);

		GhidraState state = new GhidraState(tool, project, program,
			new ProgramLocation(program, set.getMinAddress()), new ProgramSelection(set), null);
		try {
			ResourceFile sourceFile = GhidraScriptUtil.findScriptByName(scriptName);
			if (sourceFile == null) {
				throw new IllegalAccessException("Couldn't find script");
			}
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
			if (provider == null) {
				throw new IllegalAccessException("Couldn't find script provider");
			}

			PrintWriter writer = getOutputMsgStream(tool);

			GhidraScript script = provider.getScriptInstance(sourceFile, writer);
			script.set(state, monitor, writer);

			// This code was added so the analyzer won't print script messages to console
			// This also adds the ability to pass the option to add or not add bookmarks to the script
			String[] scriptArguments = { "false", String.valueOf(createBookmarksEnabled) };
			script.runScript(scriptName, scriptArguments);

			return true;
		}
		catch (IllegalAccessException e) {
			Msg.warn(this, "Unable to access script: " + scriptName, e);
		}
		catch (InstantiationException e) {
			Msg.warn(this, "Unable to instantiate script: " + scriptName, e);
		}
		catch (ClassNotFoundException e) {
			Msg.warn(this, "Unable to locate script class: " + e.getMessage(), e);
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (Exception e) {
			Msg.warn("Error running script: " + scriptName + "\n" + e.getMessage(), e);
			e.printStackTrace();
		}

		return false;
	}

	private Project findProject(PluginTool tool) {
		if (tool != null) {
			return tool.getProject();
		}
		return null;
	}

	private PrintWriter getOutputMsgStream(PluginTool tool) {
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdOut();
			}
		}
		return new PrintWriter(System.out);
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);
	}
}
