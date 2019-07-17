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
package ghidra.app.plugin.core.programtree;

import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.module.ComplexityDepthModularizationCmd;
import ghidra.app.cmd.module.DominanceModularizationCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.BlockModelService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 *
 * Provides actions for organizing the program tree based on various algorithms.  Currently, there
 * are two algorithms:
 * 
 * Dominance: organizes the functions in a program such that a function is in a subtree of another
 * function if all call paths to that function must past through the parent funciton.
 * 
 * Complexity Depth: organizes the functions into "levels" from the bottom up.  All leaf functions are
 * in the same lowest level (highest number, call it level N).  All functions that only call leaf functions
 * are in the next higher level, N-1.  Functions in the highest level (labeled level 0) are those furthest
 * from the leaves. 
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Program Tree Modularization Plugin",
	description = "Provides actions for orgainizing a program tree into modules or fragments.  " +
			"Currently there are two organizations, dominance and complexity depth",
	servicesRequired = { BlockModelService.class }
)
//@formatter:on
public class ProgramTreeModularizationPlugin extends ProgramPlugin {

	public ProgramTreeModularizationPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
	protected void init() {
		createActions();
	}

	/**
	 * Method createActions.
	 */
	private void createActions() {
		DockingAction createDominanceTreeAction =
			new DockingAction("Create Dominance Tree", getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					applyDominanceAlgorithm((ProgramNode) context.getContextObject());
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					Object contextObj = context.getContextObject();
					if (contextObj instanceof ProgramNode) {
						return ((ProgramNode) contextObj).getProgram() != null;
					}
					return false;
				}
			};

		createDominanceTreeAction.setPopupMenuData(new MenuData(new String[] { "Modularize By",
			"Dominance" }, "select"));
		createDominanceTreeAction.setHelpLocation(new HelpLocation("ProgramTreePlugin",
			"Create_Dominance_Tree"));
		tool.addAction(createDominanceTreeAction);

		DockingAction complexityDepthTreeAction =
			new DockingAction("Create Complexity Depth Tree", getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					applyComplexityDepthAlgorithm((ProgramNode) context.getContextObject());
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					Object contextObj = context.getContextObject();
					if (contextObj instanceof ProgramNode) {
						return ((ProgramNode) contextObj).getProgram() != null;
					}
					return false;
				}
			};

		complexityDepthTreeAction.setPopupMenuData(new MenuData(new String[] { "Modularize By",
			"Complexity Depth" }, "select"));
		complexityDepthTreeAction.setHelpLocation(new HelpLocation("ProgramTreePlugin",
			"Complexity_Depth"));
		tool.addAction(complexityDepthTreeAction);
	}

	/**
	 * Method createTree.
	 */
	private void applyDominanceAlgorithm(ProgramNode node) {
		BlockModelService blockModelService = tool.getService(BlockModelService.class);

		DominanceModularizationCmd cmd =
			new DominanceModularizationCmd(node.getGroupPath(), node.getGroup().getTreeName(),
				currentSelection, blockModelService.getActiveSubroutineModel());
		tool.executeBackgroundCommand(cmd, currentProgram);
	}

	/**
	 * Method createTree.
	 */
	private void applyComplexityDepthAlgorithm(ProgramNode node) {
		BlockModelService blockModelService = tool.getService(BlockModelService.class);

		ComplexityDepthModularizationCmd cmd =
			new ComplexityDepthModularizationCmd(node.getGroupPath(),
				node.getGroup().getTreeName(), currentSelection,
				blockModelService.getActiveSubroutineModel());
		tool.executeBackgroundCommand(cmd, currentProgram);
	}

}
