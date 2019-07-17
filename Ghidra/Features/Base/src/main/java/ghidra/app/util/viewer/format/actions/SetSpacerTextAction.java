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
package ghidra.app.util.viewer.format.actions;

import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.SpacerFieldFactory;
import ghidra.app.util.viewer.format.FieldHeaderLocation;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class SetSpacerTextAction extends DockingAction {

    public SetSpacerTextAction( String owner ) {
        super( "SetTextAction", owner );
        
        setPopupMenuData( new MenuData( new String[] { "Set Text" }, null, null ) );
        setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Set_Spacer_Text"));
    }
    
    @Override
    public void actionPerformed( ActionContext context ) {
        FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
        FieldFactory fieldFactory = loc.getFieldFactory();
        SpacerFieldFactory spacerFactory = (SpacerFieldFactory) fieldFactory;
        spacerFactory.setText();
    }

    @Override
    public boolean isAddToPopup(ActionContext context) {
        if ( !(context.getContextObject() instanceof FieldHeaderLocation) ) {
            return false;
        }

        FieldHeaderLocation loc = (FieldHeaderLocation) context.getContextObject();
        FieldFactory fieldFactory = loc.getFieldFactory();
        return (fieldFactory instanceof SpacerFieldFactory);
    }
}
