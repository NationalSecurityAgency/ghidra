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

import docking.ActionContext;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class ShowComponentPathAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Show Component Path";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static String DESCRIPTION =
		"Show the category for the selected component's data type";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };
	private static String[] MENU_PATH = new String[] { ACTION_NAME };

	public ShowComponentPathAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, MENU_PATH, null);
		setDescription(DESCRIPTION);
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		String message = " ";
		int index = model.getMinIndexSelected();
		DataTypeComponent dtc = model.getComponent(index);
		if (dtc != null) {
			DataType dt = dtc.getDataType();
			message =
				dt.getDisplayName() + " is in category \"" + dt.getCategoryPath().getPath() + "\".";

		}
		model.setStatus(message, false);
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isSingleComponentRowSelection());
	}
}
