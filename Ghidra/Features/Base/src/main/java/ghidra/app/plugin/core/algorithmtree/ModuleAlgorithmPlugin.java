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
package ghidra.app.plugin.core.algorithmtree;

import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.module.ModuleAlgorithmCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.BlockModelServiceListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
/**
 *
 * Applies the "module" algorithm to a Folder or Fragment. This algorithm first
 * applies the Multiple Entry Point Subroutine model, which generates fragments;
 * then the Partitioned Code Subroutine model is applied to the fragments.
 * 
 *    
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Apply Module Algorithm to a folder or fragment",
	description = "This plugin applies the \"module\" algorithm "+
			" to a Folder or Fragment in a program tree. This algorithm "+
			"first applies the Multiple Entry Point Subroutine model, "+
			"which generates fragments; then the algorithm applies the "+
			"Partitioned Code Subroutine model to these fragments.",
	servicesRequired = { BlockModelService.class }
)
//@formatter:on
public class ModuleAlgorithmPlugin extends ProgramPlugin implements BlockModelServiceListener {
	
//	private SelectAlgorithmAction createTreeAction;
	private DockingAction[] actions;
	private BlockModelService blockModelService;

	public ModuleAlgorithmPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
    protected void init() {
        blockModelService = tool.getService(BlockModelService.class);
        blockModelService.addListener(this);
        updateSubroutineActions();
    }
    
	@Override
    public void dispose() {
		super.dispose();
		if (blockModelService != null) {
			blockModelService.removeListener(this);
			blockModelService = null;
		}
	}
    
	private void updateSubroutineActions() {
    	
    	// Remove old actions
    	if (actions != null) {
    		for (int i = 0; i < actions.length; i++) {
    			tool.removeAction(actions[i]);  
    			actions[i] = null;
    		}
    		actions = null;
    	}
    	HelpLocation loc = new HelpLocation("ProgramTreePlugin", "Modularize_By_Subroutine");
    	
    	// Create subroutine actions for each subroutine provided by BlockModelService
        final String[] subModels = blockModelService.getAvailableModelNames(BlockModelService.SUBROUTINE_MODEL);
       	if (subModels.length > 1) {  // Not needed if only one subroutine model
       		actions = new DockingAction[subModels.length];
	        for (int i = 0; i < subModels.length; i++) {
	        	final String modelName = subModels[i];
	            actions[i] = new DockingAction("Modularize By Subroutine [" + modelName + "]", this.getName()) {
	            	@Override
	            	public void actionPerformed(ActionContext context) {
                       	applyModuleAlgorithm(modelName, context.getContextObject());
	            	}
	            	@Override
	            	public boolean isEnabledForContext(ActionContext context) {
	            		if (context.getContextObject() instanceof ProgramNode) {
	            			return super.isEnabledForContext(context);
	            		}
	            		return false;
	            	}
	            };
// ACTIONS - auto generated
	            actions[i].setPopupMenuData( new MenuData( 
	            	new String[]{"Modularize By", "Subroutine", subModels[i]}, 
	            	null, 
	            	"select" ) );

        		tool.addAction(actions[i]); 
        		actions[i].setEnabled(currentProgram != null);
        		actions[i].setHelpLocation(loc);
	        }
       	} else {
       		actions = new DockingAction[1];
       		actions[0] = new DockingAction("Modularize By Subroutine", this.getName()) {
            	@Override
            	public void actionPerformed(ActionContext context) {
                   	applyModuleAlgorithm(null, context.getContextObject());
            	}
            	@Override
            	public boolean isEnabledForContext(ActionContext context) {
            		if (context.getContextObject() instanceof ProgramNode) {
            			return super.isEnabledForContext(context);
            		}
            		return false;
            	}
       		};
       		
       		actions[0].setPopupMenuData( new MenuData( 
       		    new String[] {"Modularize By", "Subroutine" }, "select" ) );
       		
            tool.addAction(actions[0]);	
    		actions[0].setEnabled(currentProgram != null); 
    		actions[0].setHelpLocation(loc);
       	}
    }
    

	/**
	 * Method createTree.
	 */
	private void applyModuleAlgorithm(String modelName, Object activeObject) {

		ProgramNode node = (ProgramNode)activeObject;
		
		ModuleAlgorithmCmd cmd = new ModuleAlgorithmCmd(node.getGroupPath(), 
										node.getGroup().getTreeName(), blockModelService, modelName);
		cmd.setPluginTool(tool);
		tool.executeBackgroundCommand(cmd, currentProgram);
	}
	

	/**
	 * @see ghidra.app.plugin.ProgramPlugin#programDeactivated(Program)
	 */
	@Override
    protected void programDeactivated(Program program) {
		if (actions != null) {
			for (int i = 0; i < actions.length; i++) {
				actions[i].setEnabled(false);
			}
		}
	}

	/**
	 * @see ghidra.app.plugin.ProgramPlugin#programActivated(Program)
	 */
	@Override
    protected void programActivated(Program program) {
		if (actions != null) {
			for (int i = 0; i < actions.length; i++) {
				actions[i].setEnabled(true);
			}
		}
	}

	/**
	 * @see ghidra.app.services.BlockModelServiceListener#modelAdded(java.lang.String, int)
	 */
	public void modelAdded(String modeName, int modelType) {
		if (modelType == BlockModelService.SUBROUTINE_MODEL) {
			updateSubroutineActions();
		}
	}

	/**
	 * @see ghidra.app.services.BlockModelServiceListener#modelRemoved(java.lang.String, int)
	 */
	public void modelRemoved(String modeName, int modelType) {
		if (modelType == BlockModelService.SUBROUTINE_MODEL) {
			updateSubroutineActions();
		}
	}

}
