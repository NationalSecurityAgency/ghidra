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

import docking.action.*;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

class CreateArrayAction extends ListingContextAction {

	private static final KeyStroke DEFAULT_KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_OPEN_BRACKET, 0);
	private FunctionPlugin plugin;

	public CreateArrayAction(FunctionPlugin plugin) {
		super("Define Array", plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		setPopupMenu(plugin.getDataActionMenuName(null));
		setHelpLocation(new HelpLocation(plugin.getName(), "DataType"));

		initKeyStroke(DEFAULT_KEY_STROKE);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	private void setPopupMenu(String name) {
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, "Array..." }, null, "Array"));
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection()) {
			return false;
		}
		ProgramLocation location = context.getLocation();
		if (plugin.isValidDataLocation(location)) {
			setPopupMenu(plugin.getDataActionMenuName(location));
			return true;
		}
		if (location instanceof VariableLocation) {
			setPopupMenu(plugin.getDataActionMenuName(location));
			return true;
		}
		return false;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {

		ProgramLocation loc = context.getLocation();
		Function fun = plugin.getFunction(context);
		if (loc instanceof FunctionSignatureFieldLocation) {
			DataType dt = fun.getReturnType();
			if (dt == DataType.VOID) {
				dt = DataType.DEFAULT;
			}
			if (dt.getLength() < 1) {
				return;
			}
			int n = getNumElements(dt, Integer.MAX_VALUE, 1);
			if (n == 0) {
				return;
			}
			Array array = new ArrayDataType(dt, n, dt.getLength());
			plugin.createData(array, context, false);
		}
		else if (loc instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) loc;
			Variable var = varLoc.getVariable();
			if (var.isStackVariable()) {
				DataType dt = var.getDataType();
				int len = var.getLength();
				int defaultElements = plugin.getMaxStackVariableSize(fun, var);
				if (defaultElements <= 0) {
					defaultElements = 1;
				}
				int n = getNumElements(dt, Integer.MAX_VALUE, defaultElements);
				if (n == 0) {
					return;
				}
				Array array = new ArrayDataType(dt, n, len);
				plugin.createData(array, context, true);
			}
		}
	}

	/**
	 * Get the number of elements to create from the user.
	 */
	private int getNumElements(DataType dt, int maxElements, int initial) {
		NumberInputDialog dialog =
			new NumberInputDialog(dt.getDisplayName() + " Elements", initial, 1, maxElements);

		if (!dialog.show()) {
			return 0;  // cancelled
		}

		return dialog.getValue();
	}
}
