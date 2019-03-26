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

import ghidra.util.exception.UsrException;

import java.awt.Event;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.KeyBindingData;


/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class MoveUpAction extends CompositeEditorTableAction {

    private final static ImageIcon moveUpIcon = ResourceManager.loadImage("images/up.png");
    private final static String ACTION_NAME = "Move Components Up";
    private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
    private final static String DESCRIPTION = "Move selected components up";
    private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_UP, Event.ALT_MASK);
    private static String[] popupPath = new String[] { ACTION_NAME };

    public MoveUpAction(CompositeEditorProvider provider) {
        super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, popupPath, null, moveUpIcon);
        setDescription(DESCRIPTION);
        setKeyBindingData( new KeyBindingData( keyStroke ) );
		adjustEnablement();
    }
    
    @Override
    public void actionPerformed(ActionContext context) {
		try {
			model.moveUp();
		} catch (UsrException e1) {
			model.setStatus(e1.getMessage(), true);
		}
		requestTableFocus();
    }
    
    @Override
    public void adjustEnablement() {
        setEnabled(model.isMoveUpAllowed());
    }
    
}

