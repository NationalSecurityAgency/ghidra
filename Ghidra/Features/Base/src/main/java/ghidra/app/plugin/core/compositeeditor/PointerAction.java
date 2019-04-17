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
package ghidra.app.plugin.core.compositeeditor;

import static docking.KeyBindingPrecedence.DefaultLevel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.UsrException;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class PointerAction extends CompositeEditorTableAction {

    private final static String ACTION_NAME = "Create Pointer";
    private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
    private final static String DESCRIPTION = "Create a pointer(s) on the selection";
    private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_P, 0);
    private static DataType POINTER_DT = new PointerDataType();

    public PointerAction(CompositeEditorProvider provider) {
        super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, null, null, null);
        setDescription(DESCRIPTION);
        setKeyBindingData( new KeyBindingData( keyStroke, DefaultLevel ) );
        adjustEnablement();
    }
    
	@Override
    public void actionPerformed(ActionContext context) {
		try {
			model.add(POINTER_DT);
		} catch (UsrException e1) {
			model.setStatus(e1.getMessage());
		}
		requestTableFocus();
    }
    
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		// Do nothing since we always want it enabled so the user gets a "doesn't fit" message.
		return model.getRowCount() > 0 
			&& model.hasSelection() 
			&& model.isContiguousSelection();
	}
	
	@Override
    public void adjustEnablement() {
		// Allow the user to get a "doesn't fit" message on contiguous selection.
		// Also allow message indicating you must have a selection.
		boolean hasSelection = model.hasSelection();
		boolean enable = model.getRowCount() > 0 
					&& (!hasSelection || (hasSelection && model.isContiguousSelection()));
        setEnabled(enable);
    }
}

