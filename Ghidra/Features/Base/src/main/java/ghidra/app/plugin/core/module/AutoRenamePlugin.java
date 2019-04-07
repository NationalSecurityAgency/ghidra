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
package ghidra.app.plugin.core.module;

import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.module.RenameCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.app.services.ProgramTreeService;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * Plugin provides the following Fragment rename actions:
 *   1.  Automatically rename selected Program Fragments to match the
 *       minimum address Label within each fragment.
 *   2.  Using the active LabelFieldLocation within the code viewer,
 *       rename the corresponding fragment using the label.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Rename Fragment",
	description = "Rename a fragment in the program tree viewer with either the " +
			"selected label within the fragment or with the minimum " +
			"address label in that fragment.",
	servicesRequired = { ProgramTreeService.class }
)
//@formatter:on
public class AutoRenamePlugin extends ProgramPlugin {

    // Group with Program Tree rename (see ghidra.app.plugin.programtree.ActionManager)
    private final static String GROUP_NAME = "delete";

    // Auto Rename Action info
    private final static String[] AUTO_RENAME_MENUPATH = new String[] { "Auto Rename" };
    private AutoRenameAction autoRenameAction;

    // Auto Rename with Label Action
    private final static String[] AUTO_LBL_RENAME_MENUPATH = new String[] { "Rename Fragment to Label" };
    private DockingAction autoLblRenameAction;

    private ProgramTreeService treeService;

    /**
     * Constructor.
     */
    public AutoRenamePlugin(PluginTool tool) {
        super(tool, true, false);
        createActions();
    }

    /**
     * Set up Actions
     */
    private void createActions() {

        // Fragment Auto-Rename Action
        autoRenameAction = new AutoRenameAction(getName());
        
        // Fragment Rename Action (using active LabelFieldLocation)
        autoLblRenameAction = new AutoLableRenameAction(getName());
        tool.addAction(autoRenameAction);
        tool.addAction(autoLblRenameAction);

    }

    @Override
    protected void init() {
        treeService = tool.getService(ProgramTreeService.class);
    }

    /**
     * Perform Fragment Auto-Rename on selected Fragments.
     * Rename is performed on all selected Fragments within Program Tree.
     */
    void autoRenameCallback(ActionContext context) {

        Object obj = context.getContextObject();
        if (obj instanceof ProgramNode) {
            ProgramNode node = (ProgramNode) obj;

            CompoundCmd cmd = new CompoundCmd("Auto Rename Fragment(s)");
            SymbolTable symTable = currentProgram.getSymbolTable();

            // Find selected Fragments
            TreePath[] selectedPaths = node.getTree().getSelectionPaths();
            boolean ignoreDuplicateNames = (selectedPaths.length > 1);
            for (int i = 0; i < selectedPaths.length; i++) {
                ProgramNode n = (ProgramNode) selectedPaths[i].getLastPathComponent();
                if (!n.isFragment())
                    continue;

                // Rename Fragment using minimum address label	
                ProgramFragment f = n.getFragment();
                Address a = f.getMinAddress();
                if (a == null)
                    continue; // empty Fragment
                Symbol s = symTable.getPrimarySymbol(a);
                if (s != null) {
                    cmd.add(new RenameCmd(f.getTreeName(), false, f.getName(), s.getName(), 
                    	ignoreDuplicateNames));
                }
            }

            if (cmd.size() > 0 && !tool.execute(cmd, currentProgram)) {
                tool.setStatusInfo("Error renaming fragment: " + cmd.getStatusMsg());
            }
        }
    }

    /**
     * Perform Fragment Rename based upon the active LabelFieldLocation object.
     */
    void autoLabelRenameCallback(ListingActionContext context) {

        // Get selected fragment
    	ProgramLocation location = context.getLocation();
        if (location instanceof LabelFieldLocation && currentProgram != null) {

            LabelFieldLocation labelField = (LabelFieldLocation) location;
            String label = labelField.getName();
            String treeName = treeService.getViewedTreeName();
            ProgramFragment fragment = currentProgram.getListing().getFragment(treeName, labelField.getAddress());
            if (!label.equals(fragment.getName())) {
                RenameCmd cmd = new RenameCmd(treeName, false, fragment.getName(), label);
                if (!tool.execute(cmd, currentProgram)) {
                    tool.setStatusInfo("Error renaming fragment: " + cmd.getStatusMsg());
                }
            }
        }
    }
    /**
     * Defines a Fragment Auto-Rename action and controls the availability of the
     * action within popup menus.
     */
    class AutoRenameAction extends DockingAction {

        /**
         * Construct a new PluginAction
         * @param owner owner of the action
         * @param plugin instance of module sort plugin
         */
        public AutoRenameAction(String owner) {
            super("Rename Fragment from Program Tree View", owner);
            setHelpLocation(new HelpLocation("ProgramTreePlugin", "AutoRename"));
            setPopupMenuData( new MenuData( 
            	AUTO_RENAME_MENUPATH, 
            	null, 
            	"delete" ) );

            setDescription("Rename a fragment in the program tree viewer with the minimum address label in that fragment.");
            setEnabled(true); // always enabled

        }

        /**
         * Determine if the Fragment Auto-Rename action should be visible within
         * the popup menu for the selected nodes within the Program Tree View.
         * @param activeObj the object under the mouse location for the popup.
         * @return true if action should be made visible in popup menu.
         */
    	@Override
        public boolean isEnabledForContext(ActionContext context) {
    		Object activeObj = context.getContextObject();
    		// Only make action available for selections which contain a minimum of one Fragment.
    		if (activeObj != null && activeObj instanceof ProgramNode) {
    			ProgramNode node = (ProgramNode) activeObj;
    			if (node.getProgram() != null) {
    				// Ensure that at least one Fragment is selected within a multi-select
    				TreePath[] selectedPaths = node.getTree().getSelectionPaths();
    				for (int i = 0; i < selectedPaths.length; i++) {
    					ProgramNode n =
    						(ProgramNode) selectedPaths[i].getLastPathComponent();
    					if (n.isFragment())
    						return true;
    				}
    			}
    		}
    		return false;
    	}
    	@Override
    	public void actionPerformed(ActionContext context) {
    		autoRenameCallback(context);
    	}
    }
    class AutoLableRenameAction extends ListingContextAction {

		public AutoLableRenameAction(String owner) {
			super("Rename Fragment from Code Browser", owner);
			setPopupMenuData( new MenuData( 
				AUTO_LBL_RENAME_MENUPATH, null, GROUP_NAME ) );

	        setDescription("Rename a fragment in the program tree viewer with the selected label within the fragment.");
	        setHelpLocation(new HelpLocation("ProgramTreePlugin", "RenameFragmentToLabel"));
		}
		@Override
		public boolean isEnabledForContext(ListingActionContext context) {
			return context.getLocation() instanceof LabelFieldLocation;
		}
		@Override
		public void actionPerformed(ListingActionContext context) {
            autoLabelRenameCallback(context);
		}
    }
}
