/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class GraphASTControlFlowAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;
	private final Plugin plugin;

	public GraphASTControlFlowAction(String owner, Plugin plugin, DecompilerController controller) {
		super("Graph AST Control Flow", owner);
		this.plugin = plugin;
		this.tool = plugin.getTool();
		this.controller = controller;
		setMenuBarData(new MenuData(new String[] { "Graph AST Control Flow" }, "graph"));

	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		return controller.getFunction() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(),
				context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked", "You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

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
		ASTGraphTask task =
			new ASTGraphTask(graphService, !reuseGraph, codeLimitPerBlock, locationAddr,
				highFunction, ASTGraphTask.CONTROL_FLOW_GRAPH);
		new TaskLauncher(task, tool.getToolFrame());
	}

}
