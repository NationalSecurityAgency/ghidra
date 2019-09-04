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
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.GraphService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

public class GraphASTControlFlowAction extends AbstractDecompilerAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public GraphASTControlFlowAction(Plugin plugin, DecompilerController controller) {
		super("Graph AST Control Flow");
		this.tool = plugin.getTool();
		this.controller = controller;
		setMenuBarData(new MenuData(new String[] { "Graph AST Control Flow" }, "graph"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return controller.getFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		GraphService graphService = tool.getService(GraphService.class);
		if (graphService == null) {
			Msg.showError(this, tool.getToolFrame(), "AST Graph Failed",
				"GraphService not found: Please add a graph service provider to your tool");
			return;
		}

		// TODO: Options should really be obtained from graph service
		Options options = tool.getOptions("Graph");
		boolean reuseGraph = options.getBoolean("Reuse Graph", false);
		int codeLimitPerBlock = options.getInt("Max Code Lines Displayed", 10);
		HighFunction highFunction = controller.getHighFunction();
		Address locationAddr = controller.getLocation().getAddress();
		ASTGraphTask task = new ASTGraphTask(graphService, !reuseGraph, codeLimitPerBlock,
			locationAddr, highFunction, ASTGraphTask.CONTROL_FLOW_GRAPH);
		new TaskLauncher(task, tool.getToolFrame());
	}

}
