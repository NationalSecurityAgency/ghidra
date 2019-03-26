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

import ghidra.util.Msg;
import ghidra.util.exception.UsrException;

import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;

import resources.ResourceManager;


public class ClearAction extends CompositeEditorTableAction {

	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static ImageIcon CLEAR_ICON = ResourceManager.loadImage("images/erase16.png");
    private final static String[] popupPath = new String[] { "Clear" };
	private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_C, 0);

	/**
	 * 
	 * @param owner
	 * @param cycleGroup
	 */
	public ClearAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + "Clear Components", 
			  GROUP_NAME, popupPath, null, CLEAR_ICON);
			  
		setDescription("Clear the selected components");
		setKeyBindingData(new KeyBindingData(keyStroke));
		adjustEnablement();
	}
	
	/* (non-Javadoc)
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	 @Override
    public void actionPerformed(ActionContext context) {
		try {
			model.clearSelectedComponents();
		} catch (OutOfMemoryError memExc) {
			String errMsg = "Couldn't clear components. Out of memory.";
			Msg.showError(this, null, "Out of Memory", errMsg, memExc);
		} catch (UsrException ue) {
			model.setStatus(ue.getMessage());
		}
		requestTableFocus();
	 }
    
	 /* (non-Javadoc)
	  * @see ghidra.app.plugin.datamanager.editor.CompositeEditorAction#adjustEnablement()
	  */
	 @Override
    public void adjustEnablement() {
		 setEnabled(model.isClearAllowed());
	 }
	 
}
