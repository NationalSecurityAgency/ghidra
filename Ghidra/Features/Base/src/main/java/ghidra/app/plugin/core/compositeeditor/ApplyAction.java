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
package ghidra.app.plugin.core.compositeeditor;

import javax.swing.ImageIcon;

import docking.ActionContext;
import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.program.model.data.InvalidDataTypeException;
import resources.ResourceManager;

/**
 * ApplyAction is an action for applying editor changes. 
 */
public class ApplyAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Apply Editor Changes";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static ImageIcon ICON = ResourceManager.loadImage("images/disk.png");
	private final static String[] POPUP_PATH = new String[] { "Apply Edits" };

	public ApplyAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);

		setDescription("Apply editor changes");
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!model.isValidName()) {
			model.setStatus("Name is not valid.", true);
			return;
		}
		try {
			model.apply();
		}
		catch (EmptyCompositeException e1) {
			model.setStatus(e1.getMessage(), true);
		}
		catch (InvalidDataTypeException e1) {
			model.setStatus(e1.getMessage(), true);
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		boolean hasChanges = model.hasChanges();
		boolean validName = model.isValidName();
		setEnabled(hasChanges && validName);
	}
}
