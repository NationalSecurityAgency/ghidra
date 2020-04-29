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
package ghidra.framework.analysis;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.Project;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@ExtensionPointProperties(exclude = true) // exclude class from extension point discovery because it has to be directly instantiated in order to wrap the supplied script
public class GhidraScriptAnalyzerAdapter extends AbstractAnalyzer {

	private ResourceFile scriptFile;
	private GhidraScript script;
	private PrintWriter writer;

	public GhidraScriptAnalyzerAdapter(ResourceFile file, AnalyzerType analyzerType, int priority) {
		super("Script: " + file.getName(), getDescription(file), analyzerType);
		this.scriptFile = file;
		setDefaultEnablement(true);
		setPriority(new AnalysisPriority(priority));
		writer = new PrintWriter(System.out);
		script = getGhidraScript();
	}

	private static String getDescription(ResourceFile file) {
		return GhidraScriptUtil.newScriptInfo(file).getDescription();
	}

	public void setPrintWriter(PrintWriter writer) {
		this.writer = writer;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		if (script == null) {
			return false;
		}
		ProgramLocation loc = new ProgramLocation(program, set.getMinAddress());
		ProgramSelection selection = new ProgramSelection(set);

		// TODO if this API is ever used, then we need a project passed for scripts that 
		//      may need it
		Project project = null;
		GhidraState scriptState = new GhidraState(null, project, program, loc, selection, null);

		return runScript(scriptState, monitor);
	}

	private boolean runScript(GhidraState scriptState, TaskMonitor monitor) {

		ResourceFile srcFile = script.getSourceFile();
		String scriptName =
			srcFile != null ? srcFile.getAbsolutePath() : (script.getClass().getName() + ".class");

		try {
			Msg.info(this, "SCRIPT: " + scriptName);
			script.execute(scriptState, monitor, writer);
			writer.flush();
		}
		catch (Exception exc) {
			Program prog = scriptState.getCurrentProgram();
			String path = (prog != null ? prog.getExecutablePath() : "Current program is null.");
			String logErrorMsg =
				path + "\nREPORT SCRIPT ERROR: " + scriptName + " : " + exc.getMessage();
			Msg.error(this, logErrorMsg, exc);
			return false;
		}

		return true;
	}

	private GhidraScript getGhidraScript() {
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
		try {
			return provider.getScriptInstance(scriptFile, writer);
		}
		catch (Exception e) {
			Msg.error(this, "Error compiling script: " + e.getMessage(), e);
		}
		return null;
	}

	public String getScriptName() {
		return scriptFile.getName();
	}
}
