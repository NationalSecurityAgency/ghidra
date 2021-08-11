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

import static ghidra.app.plugin.core.decompile.actions.ASTGraphTask.AstGraphSubType.*;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;
public class GraphASTControlFlowAction extends AbstractDecompilerAction {

	public GraphASTControlFlowAction() {
		super("Graph AST Control Flow");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarGraph"));
		setMenuBarData(new MenuData(new String[] { "Graph AST Control Flow" }, "graph"));
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
				"Graph consumer not found: Please add a graph consumer provider to your tool");
			return;
		}

		// TODO: Options should really be obtained from graph service
		Options options = tool.getOptions("Graph");
		boolean reuseGraph = options.getBoolean("Reuse Graph", false);
		int codeLimitPerBlock = options.getInt("Max Code Lines Displayed", 10);
		HighFunction highFunction = context.getHighFunction();
		Address locationAddr = context.getLocation().getAddress();
		ASTGraphTask task = new ASTGraphTask(service, !reuseGraph, codeLimitPerBlock, locationAddr,
			highFunction, CONTROL_FLOW_GRAPH, tool);
		new TaskLauncher(task, tool.getToolFrame());
	}

}
