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
package ghidra.app.plugin.core.script;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptInfoManager;
import ghidra.app.script.ScriptInfo;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

class ScriptAction extends DockingAction {
	private static final String SCRIPT_GROUP = "_SCRIPT_GROUP_";

	private GhidraScriptMgrPlugin plugin;
	private GhidraScriptInfoManager infoManager;
	private ResourceFile script;

	/** Signals that the keybinding value has been set by the user from the GUI (used for persistence) */
	private boolean isUserDefinedKeyBinding = false;

	ScriptAction(GhidraScriptMgrPlugin plugin, ResourceFile script) {
		super(script.getName(), plugin.getName());
		this.plugin = plugin;
		this.infoManager = plugin.getProvider().getInfoManager();
		this.script = script;
		setEnabled(true);
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		refresh();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.runScript(script);
	}

	@Override
	public void setUnvalidatedKeyBindingData(KeyBindingData keyBindingData) {

		// 
		// Unobvious Dependencies!: 
		// We have two different ways the user can set the keybinding for this action: 1) By way
		// of the 'assign keybindings' action in the provider and 2) by including a keybinding
		// assignment in the metadata of the script itself.  The user-defined binding from the GUI
		// gets precedence over the script's metadata.
		//
		// Also, if we are given a data object whose keystroke is null, then we have 
		// to decide if the value is being completely cleared, or if the user has cleared 
		// the action from the GUI, in which case we should fall back to the
		// script's metadata, if it defines a keybinding.
		//	    	    
		KeyBindingData newKeyBindingData = checkForFallbackKeybindingCondition(keyBindingData);
		updateUserDefinedKeybindingStatus(newKeyBindingData);
		super.setUnvalidatedKeyBindingData(newKeyBindingData);
		plugin.getProvider().keyBindingUpdated();
	}

	@Override
	public void setKeyBindingData(KeyBindingData keyBindingData) {
		isUserDefinedKeyBinding = false; // reset
		if (keyBindingData == null) {
			// simply clearing out any keybinding data settings
			super.setKeyBindingData(keyBindingData);
			return;
		}

		setUnvalidatedKeyBindingData(keyBindingData);
	}

	private KeyBindingData checkForFallbackKeybindingCondition(KeyBindingData keyBindingData) {
		KeyStroke newKeyStroke = keyBindingData.getKeyBinding();
		if (newKeyStroke != null) {
			// we have a valid value; the current keybinding data is what we want
			return keyBindingData;
		}

		// check to see if we have a fallback value         
		ScriptInfo info = infoManager.getExistingScriptInfo(script);
		KeyStroke metadataKeyStroke = info.getKeyBinding();
		if (metadataKeyStroke == null) {
			// there is no fallback value; the current keybinding data is what we want
			return keyBindingData;
		}

		// there is a fallback metadata value, we want to make that the current keybinding
		return new KeyBindingData(metadataKeyStroke, keyBindingData.getKeyBindingPrecedence());
	}

	private void updateUserDefinedKeybindingStatus(KeyBindingData keyBindingData) {
		// we have a user defined keybinding if the keystroke for the action differs from 
		// that which is defined in the metadata of the script
		KeyStroke actionKeyStroke = keyBindingData.getKeyBinding();
		ScriptInfo info = infoManager.getExistingScriptInfo(script);
		KeyStroke metadataKeyBinding = info.getKeyBinding();
		isUserDefinedKeyBinding = !SystemUtilities.isEqual(actionKeyStroke, metadataKeyBinding);
	}

	boolean isUserDefinedKeyBinding() {
		return isUserDefinedKeyBinding;
	}

	ResourceFile getScript() {
		return script;
	}

	void refresh() {
		/* this is called during script manager initial config
		 * before any other access to script info, so we expect to
		 * create a new ScriptInfo with the next call.
		 */
		ScriptInfo info = infoManager.getScriptInfo(script);
		KeyStroke stroke = info.getKeyBinding();
		if (!isUserDefinedKeyBinding) {
			setKeyBindingData(new KeyBindingData(stroke));
		}
		Icon icon = info.getToolBarImage(false);
		if (icon != null) {
			ToolBarData data = getToolBarData();
			if (data != null) {
				data.setIcon(icon);
			}
			else {
				setToolBarData(new ToolBarData(icon, SCRIPT_GROUP));
			}
		}
		setDescription(info.getDescription());
		MenuData menuData = getMenuBarData();
		String[] oldMenuPath = menuData == null ? null : menuData.getMenuPath();
		String[] newMenuPath = info.getMenuPath();

		if (SystemUtilities.isArrayEqual(oldMenuPath, newMenuPath)) {
			return;
		}

		plugin.getTool().removeAction(this);
		if (newMenuPath != null && newMenuPath.length > 0) {
			MenuData data = getMenuBarData();
			if (data != null) {
				data.setMenuPath(newMenuPath);
			}
			else {
				setMenuBarData(new MenuData(newMenuPath, icon, SCRIPT_GROUP));
			}
		}
		else {
			setMenuBarData(null);
		}
		plugin.getTool().addAction(this);
	}
}
