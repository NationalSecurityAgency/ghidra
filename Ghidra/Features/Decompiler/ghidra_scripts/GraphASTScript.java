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
//Decompile the function at the cursor, then build data-flow graph (AST)
//@category PCode

import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphTask;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;

public class GraphASTScript extends GhidraScript {

	private Function func;
	protected HighFunction high;

	private static final String DECOMPILE = "decompile";
	private static final String NORMALIZE = "normalize";
	private static final String PARAM_ID = "paramid";
	private static final String REGISTER = "register";
	private static final String FIRSTPASS = "firstpass";
	private static final String JUMP_TABLE = "jumptable";

	@Override
	public void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			popup("Script is not running in GUI");
			return;
		}
		GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
		if (graphDisplayBroker == null) {
			Msg.showError(this, tool.getToolFrame(), "GraphAST Error",
				"No graph display providers found: Please add a graph display provider to your tool");
			return;
		}

		func = this.getFunctionContaining(this.currentAddress);
		if (func == null) {
			Msg.showWarn(this, state.getTool().getToolFrame(), "GraphAST Error",
				"No Function at current location");
			return;
		}
		String style = askChoice("Select Simplification Style", "Select Simplification Style",
			List.of(DECOMPILE, FIRSTPASS, JUMP_TABLE, NORMALIZE, PARAM_ID, REGISTER), DECOMPILE);
		buildAST(style);
		PCodeDfgGraphTask astGraphTask = createTask(graphDisplayBroker);
		astGraphTask.monitoredRun(monitor);
	}

	protected PCodeDfgGraphTask createTask(GraphDisplayBroker graphDisplayBroker) {
		return new PCodeDfgGraphTask(state.getTool(), graphDisplayBroker, high);
	}

	private void buildAST(String style) throws DecompileException {
		DecompileOptions options = new DecompileOptions();

		DecompInterface ifc = new DecompInterface();
		try {
			ifc.setOptions(options);
			if (!ifc.openProgram(this.currentProgram)) {
				throw new DecompileException("Decompiler",
					"Unable to initialize: " + ifc.getLastMessage());
			}
			ifc.setSimplificationStyle(style);
			DecompileResults res = ifc.decompileFunction(func, 30, null);
			high = res.getHighFunction();
		}
		finally {
			ifc.dispose();
		}

	}

}
