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

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;


public class DeleteAction extends CompositeEditorTableAction {

	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static ImageIcon DELETE_ICON =
		ResourceManager.loadImage("images/edit-delete.png");
    private final static String[] popupPath = new String[] { "Delete" };
	private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);

	/**
	 * 
	 * @param owner
	 */
	public DeleteAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + "Delete Components", GROUP_NAME, 
				popupPath, null, DELETE_ICON);
		
		setKeyBindingData( new KeyBindingData( keyStroke ) );
		setDescription("Delete the selected components");
		adjustEnablement();
	}
	
	/* (non-Javadoc)
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	 @Override
    public void actionPerformed(ActionContext context) {
		try {
			model.deleteSelectedComponents();
		} catch (OutOfMemoryError memExc) {
			Msg.showError(this, null, "Out of Memory", "Couldn't delete components. Out of memory.", memExc);
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
		 setEnabled(model.isDeleteAllowed());
	 }
}
