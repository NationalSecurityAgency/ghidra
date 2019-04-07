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
import ghidra.app.util.viewer.field.SpacerFieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * Action for adding SpacerFields to a FieldModel
 */
public class AddSpacerFieldAction extends DockingAction {
	private FieldHeader panel;
	
    public AddSpacerFieldAction(String owner, FieldHeader panel) {
        super("Add Spacer Field", owner, false);
        this.panel = panel;
        setPopupMenuData(new MenuData(new String[] {"Add Field", "Spacer"},"header a"));
        setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Add Field"));
    }
    @Override
	public boolean isEnabledForContext(ActionContext context) {
    	return context.getContextObject() instanceof FieldHeaderLocation;
	}

    /**
     * Method called when the action is invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
    	FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
        FieldFormatModel modelAtLocation = loc.getModel();
    	panel.setTabLock( true );
    	modelAtLocation.addFactory(new SpacerFieldFactory(), loc.getRow(), loc.getColumn());
    }

}

