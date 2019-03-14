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
package ghidra.app.plugin.core.data;

import ghidra.app.context.ListingActionContext;
import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FieldNameFieldLocation;
import ghidra.program.util.ProgramLocation;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
 
/**
 * Base class for comment actions to edit and delete comments.
 */
class RenameDataFieldAction extends DockingAction {

	private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_N,0);
	private DataPlugin plugin;
	private RenameDataFieldDialog dialog;
	
    public RenameDataFieldAction(DataPlugin plugin) {
        super("Rename Data Field", plugin.getName()); 
        dialog = new RenameDataFieldDialog(plugin);
// ACTIONS - auto generated
        setPopupMenuData( 
        	new MenuData( 
        	new String[] {"Data",  "Rename Field"},null,"BasicData" ) );

        setKeyBindingData( new KeyBindingData( 
        	KeyEvent.VK_N, 0 ) );

        this.plugin = plugin;
        setEnabled(true);
    }

    /**
     * Method called when the action is invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
    	ListingActionContext programActionContext = (ListingActionContext) context.getContextObject();
		PluginTool tool = plugin.getTool();
		Program program = programActionContext.getProgram();
		ProgramLocation loc = programActionContext.getLocation();
		Data data = program.getListing().getDataContaining(loc.getAddress());
		DataType type = data.getDataType();

		if (type instanceof Composite) {
			Composite comp = (Composite)type;
			int[] compPath = loc.getComponentPath();
			for (int i=0; i<compPath.length-1; i++) {
				DataTypeComponent subComp = comp.getComponent(compPath[i]);
				type = subComp.getDataType();
				if (type instanceof Composite)
					comp = (Composite)type;
				else
					return;
			}

			Data instance = data.getComponent(compPath);
			DataTypeComponent subComp = comp.getComponent(compPath[compPath.length-1]);
			dialog.setDataComponent(program, subComp, instance.getFieldName());
			tool.showDialog(dialog, tool.getComponentProvider(PluginConstants.CODE_BROWSER));
		}
	}

	/*
	 * @see docking.DockableAction#isValidContext(java.lang.Object)
	 */
    @Override
    public boolean isEnabledForContext(ActionContext context) {
    	Object contextObject = context.getContextObject();
		if (!(contextObject instanceof ListingActionContext)) {
			return false;
		}
		ListingActionContext programActionContext = (ListingActionContext) contextObject;
		return (programActionContext.getLocation() instanceof FieldNameFieldLocation);
	}

}
