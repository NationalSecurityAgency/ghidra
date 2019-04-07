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
package ghidra.app.plugin.core.programtree;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;

/**
 * Class for program tree actions; ensures that actions are put on a popup
 * only if the popup is over something that implements the ProgramTreeService.
 */
abstract class ProgramTreeAction extends DockingAction {

    final static int SINGLE_SELECTION=0;
    final static int MULTI_SELECTION=1;

    private int selectionType;

    ProgramTreeAction(String name, String owner, String[] defaultPopupPath, KeyStroke defaultKeyBinding) {
        this(name, owner, defaultPopupPath,
              defaultKeyBinding, MULTI_SELECTION);
    }
    ProgramTreeAction(String name, String owner,
                String[] defaultPopupPath,
                KeyStroke defaultKeyBinding,int selectionType) {
        super(name, owner);
        
        this.selectionType = selectionType;
        if (defaultKeyBinding != null) {
            setKeyBindingData( new KeyBindingData( defaultKeyBinding ) );
        }
        setEnabled(false); 
    }
    @Override
    public boolean isValidContext(ActionContext context) {
    	return context.getContextObject() instanceof ProgramNode;
    }
    @Override
    public boolean isAddToPopup(ActionContext context) {
    	return true;
    }
    /**
     * Get the selection type associated with this action.
     */
    int getSelectionType() {
        return selectionType;
    }
}
