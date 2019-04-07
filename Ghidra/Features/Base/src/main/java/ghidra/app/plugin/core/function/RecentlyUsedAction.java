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
package ghidra.app.plugin.core.function;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

public class RecentlyUsedAction extends DataAction {
	private final static KeyStroke DEFAULT_KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_Y, 0);
	private final static String GROUP_NAME = "Z_RECENT";

	public RecentlyUsedAction(FunctionPlugin plugin) {
		super("Recently Used", "Recent", new ByteDataType(), plugin);

		setHelpLocation(new HelpLocation(plugin.getName(), "Recently_Used"));
	}

	@Override
	protected KeyStroke getDefaultKeyStroke() {
		return DEFAULT_KEY_STROKE; // we have no default, but our subclasses may
	}

	@Override
	protected void initKeyStroke(KeyStroke keyStroke) {
		if (!DEFAULT_KEY_STROKE.equals(keyStroke)) {
			// user-defined keystroke
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataType recentDataType = getRecentDataType();
		if (recentDataType == null) {
			return false;
		}

		this.dataType = recentDataType;
		
		boolean enabled = super.isEnabledForContext(context);
		return enabled;
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof FunctionSignatureFieldLocation) {
			return true;
		}
		if (location instanceof VariableLocation) {
			return true;
		}
		return false;
	}

	private DataType getRecentDataType() {
		DataTypeManagerService service = plugin.getTool().getService(DataTypeManagerService.class);
		if (service == null) {
			return null;
		}
		return service.getRecentlyUsed();
	}

	@Override
	public void setPopupMenu(String name, boolean isSignatureAction) {
		DataType dt = getRecentDataType();
		String displayName = "Last Used: " + (dt == null ? "<empty>" : dt.getDisplayName());

		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT,
			displayName }, GROUP_NAME));
	}
}
