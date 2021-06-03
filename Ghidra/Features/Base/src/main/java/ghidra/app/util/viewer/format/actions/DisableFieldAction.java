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
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.format.FieldHeaderLocation;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;



/**
 * Action for disabling a field.
 */
public class DisableFieldAction extends DockingAction {
	private FieldHeaderLocation loc;
	private FieldHeader panel;

    /**
     * Constructor
	 * @param owner the action owner
     */
    public DisableFieldAction(String owner, FieldHeader panel) {
        super("Disable Field", owner, false);
        this.panel = panel;
        
        setPopupMenuData( new MenuData( new String[] {"Disable Field"}, "field" ) );
        setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Disable Field"));
	}

    @Override
    public boolean isEnabledForContext(ActionContext context) {
    	Object contextObject = context.getContextObject();
		if (contextObject instanceof FieldHeaderLocation) {
			loc = (FieldHeaderLocation)contextObject;
			FieldFactory ff = loc.getFieldFactory();
			return ff != null && ff.isEnabled(); 
		}
		return false;
    }

    @Override
    public void actionPerformed(ActionContext context) {
		FieldFactory factory = loc.getFieldFactory();
		panel.setTabLock( true );
        factory.setEnabled(false);
	}

}

