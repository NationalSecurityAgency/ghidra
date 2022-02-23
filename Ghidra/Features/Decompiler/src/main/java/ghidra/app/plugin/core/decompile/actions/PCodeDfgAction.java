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
package ghidra.app.plugin.core.decompile.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

/**
 * Action to create a PCode control data graph based on decompiler output
 */
public class PCodeDfgAction extends AbstractDecompilerAction {

	public PCodeDfgAction() {
		super("Graph PCode Data Flow");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "DataFlowGraph"));
		setMenuBarData(new MenuData(new String[] { "Graph Data Flow" }, "graph"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		if (service == null) {
			Msg.showError(this, tool.getToolFrame(), "AST Graph Failed",
				"Graph Display Broker service not found!\n" +
					"Please add a Graph Display Broker service");
			return;
		}

		HighFunction highFunction = context.getHighFunction();
		PCodeDfgGraphTask task = new PCodeDfgGraphTask(tool, service, highFunction);
		new TaskLauncher(task, tool.getToolFrame());
	}

}
