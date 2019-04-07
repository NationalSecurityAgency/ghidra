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
package ghidra.app.actions;

import javax.swing.KeyStroke;

import docking.action.DockingAction;
import docking.action.KeyBindingData;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;

/**
 * An action that can be extended in order to share keybindings.
 * <p>
 * Any group of actions that wish to share a keybinding must all use the same <tt>name</tt> and
 * default <tt>keystroke</tt> value.
 * <p>
 * As the end-user assigns keybindings, each subclass will update accordingly.
 * 
 * @see DummyKeyBindingsOptionsAction 
 */
public abstract class AbstractSharedKeybindingAction extends DockingAction
		implements OptionsChangeListener {

	protected PluginTool tool;

	protected AbstractSharedKeybindingAction(PluginTool tool, String name, String owner,
			KeyStroke defaultkeyStroke) {

		super(name, owner, false /* not keybinding managed--the dummy handles that */);
		this.tool = tool;

		DockingAction action = new DummyKeyBindingsOptionsAction(name, defaultkeyStroke);
		tool.addAction(action);

		// setup options to know when the dummy key binding is changed
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		KeyStroke optionsKeyStroke = options.getKeyStroke(action.getFullName(), defaultkeyStroke);

		if (defaultkeyStroke != null) {
			if (!defaultkeyStroke.equals(optionsKeyStroke)) {
				// user-defined keystroke
				setUnvalidatedKeyBindingData(new KeyBindingData(optionsKeyStroke));
			}
			else {
				setKeyBindingData(new KeyBindingData(optionsKeyStroke));
			}
		}
		else {
			if (optionsKeyStroke != null) {
				// user-defined keystroke
				setUnvalidatedKeyBindingData(new KeyBindingData(optionsKeyStroke));
			}
		}


		options.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		String actionName = getName();
		if (name.startsWith(actionName)) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

}
