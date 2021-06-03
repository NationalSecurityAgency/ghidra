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
package ghidra.app.util.viewer.format.actions;

import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * Action for adding all fields to the current format.
 */
public class AddAllFieldAction extends DockingAction {
	FieldHeader panel;
	
	/**
	 * Constructor takes the CodeBrowserPlugin that created it and the header
	 * component so that it can be repainted when fields are added.
	 * @param owner the action owner	
	 * @param panel the listing panel.
	 */
    public AddAllFieldAction(String owner, FieldHeader panel) {
        super("Add All Field", owner, false);
        this.panel = panel;
        setPopupMenuData(new MenuData(new String[] {"Add Field","All"}, "header a"));
		setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Add Field"));
    }
    @Override
	public boolean isEnabledForContext(ActionContext context) {
        Object contextObject = context.getContextObject();
        if ( !(contextObject instanceof FieldHeaderLocation) ) {
            return false;
        }
        FieldHeaderLocation loc = (FieldHeaderLocation) contextObject;
        FieldFormatModel modelAtLocation = loc.getModel();
        
        FieldFactory[] allFactories = modelAtLocation.getAllFactories();
        return allFactories.length > 1;
	}

    @Override
    public boolean isValidContext(ActionContext context) {
        return (context.getContextObject() instanceof FieldHeaderLocation);
    }
    
    /**
     * Method called when the action is invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
    	panel.setTabLock( true );
    	FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
        FieldFormatModel modelAtLocation = loc.getModel();
        modelAtLocation.addAllFactories();
	}

}

