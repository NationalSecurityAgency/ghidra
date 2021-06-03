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

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import ghidra.program.model.data.CycleGroup;

/**
 * Action to apply a data type cycle group. For use in the composite data type editor.
 */
public class CycleGroupAction extends CompositeEditorTableAction {

	private final static String GROUP_NAME = DATA_ACTION_GROUP;
	private CycleGroup cycleGroup;

	public CycleGroupAction(CompositeEditorProvider provider, CycleGroup cycleGroup) {
		super(provider, cycleGroup.getName(), GROUP_NAME,
			new String[] { "Cycle", cycleGroup.getName() },
			new String[] { "Cycle", cycleGroup.getName() }, null);
		this.cycleGroup = cycleGroup;
		getPopupMenuData().setParentMenuGroup(GROUP_NAME);
		initKeyStroke(cycleGroup.getDefaultKeyStroke());
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	public CycleGroup getCycleGroup() {
		return cycleGroup;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		model.cycleDataType(cycleGroup);
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(true);
	}

	@Override
	public String getHelpName() {
		return "Cycle";
	}
}
