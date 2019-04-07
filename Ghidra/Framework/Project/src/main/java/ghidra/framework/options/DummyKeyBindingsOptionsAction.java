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
package ghidra.framework.options;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.KeyBindingData;

/**
 * A dummy action that allows key bindings to be edited through the key bindings options
 * <b>without</b> requiring the user to implement a system action that will be added to the tool.
 * Without this class the only editable tool key bindings are those that have corresponding
 * {@link DockingAction}s added to the tool.
 * <p>
 * A typical usage of this class: Suppose a plugin has an action that it adds to the tool, 
 * which is logically the same action (with the same name) that a second plugin adds to the tool.  
 * Both of these actions are 
 * logically equivalent and share the same default key binding.  Since these actions are 
 * logically the same, then they should share the same key binding and only have one entry 
 * in the key binding options, instead of two.  This class enables both actions to have key 
 * bindings assigned via one dummy action.  <b>To do this each of the above primary actions will set 
 * themselves to not manage key bindings</b>, so they don't appear in the key bindings options,  
 * and will then create an instance of this class and register it with the tool.  Then, each of 
 * those primary actions will listen for options changes to know when the user has edited
 * the key binding of the dummy action.  The following snippet is an example of this usage,
 * taken from the constructor of a DockingAction:
 * <pre>
 *       // setup key binding management
 *       setKeyBindingManaged( false ); // our dummy will handle this task, not us
 *       KeyStroke keyStroke = ...;
 *       PluginTool tool = plugin.getTool();
 *       tool.addAction( new DummyKeyBindingsOptionsAction( ACTION_NAME, keyStroke ) );
 *       
 *       // setup options to know when the dummy key binding is changed
 *       Options options = tool.getOptions(ToolConstants.KEY_BINDINGS);        
 *       KeyStroke optionsKeyStroke = options.getKeyStroke( "Tool", ACTION_NAME, keyStroke );
 *       
 *       if (!keyStroke(optionsKeyStroke)) {
 *           // user-defined keystroke
 *           setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
 *       }
 *       else {
 *           setKeyBindingData(new KeyBindingData(keyStroke));
 *       }
 *
 *       options.addOptionsChangeListener( ... );
 * </pre>
 * 
 * And for changes to the options keybinding value:
 * <pre>
 *  public void optionsChanged(Options options, String name, Object oldValue, Object newValue) {
 *      KeyStroke keyStroke = (KeyStroke) newValue;
 *      if (name.startsWith(KEY_BINDING_NAME)) {
 *          setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
 *      }
 *  }
 * </pre>
 */
public class DummyKeyBindingsOptionsAction extends DockingAction {
	public static final String DEFAULT_OWNER = "Tool";

	/**
	 * Creates a new dummy action by the given name and default keystroke value.
	 * @param name The name of the action--this will be displayed in the options as the name of
	 *             key binding's action.
	 * @param defaultKeyStroke The default keystroke value for this action.  This value may be null.
	 */
	public DummyKeyBindingsOptionsAction(String name, KeyStroke defaultKeyStroke) {
		super(name, DEFAULT_OWNER);

		if (defaultKeyStroke != null) {
			setKeyBindingData(new KeyBindingData(defaultKeyStroke));
		}

		// Dummy keybinding actions don't have help--the real action does
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// no-op; this is a dummy!
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return false;
	}
}
