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
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.data.CycleGroup;

/**
 * Action to apply a data type cycle group.
 * For use in the composite data type editor.
 * This action has help associated with it.
 */
public class CycleGroupAction extends CompositeEditorTableAction implements OptionsChangeListener {

	private final static String GROUP_NAME = CYCLE_ACTION_GROUP;
	private CycleGroup cycleGroup;

	/**
	 * Creates an action for applying a data type cycle group.
	 * @param owner the plugin that owns this action
	 * @param cycleGroup the data type cycle group
	 */
	public CycleGroupAction(CompositeEditorProvider provider, CycleGroup cycleGroup) {
		super(provider, cycleGroup.getName(), GROUP_NAME,
			new String[] { "Cycle", cycleGroup.getName() },
			new String[] { "Cycle", cycleGroup.getName() }, null);
		this.cycleGroup = cycleGroup;

		// register an action that allows users to edit keystrokes
		DockingAction action = new DummyKeyBindingsOptionsAction(cycleGroup.getName(),
			cycleGroup.getDefaultKeyStroke());
		tool.addAction(action);
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		KeyStroke defaultKeyStroke = cycleGroup.getDefaultKeyStroke();
		KeyStroke keyStroke = options.getKeyStroke(action.getFullName(), defaultKeyStroke);
		options.addOptionsChangeListener(this);

		if (!defaultKeyStroke.equals(keyStroke)) {
			// user-defined keystroke
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}

		adjustEnablement();
	}

	/**
	 * Gets the data type cycle group for this action.
	 */
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

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (name.startsWith(cycleGroup.getName())) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}
}
