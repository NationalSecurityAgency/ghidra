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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

/**
 * Action triggered from a specific token in the decompiler window to change the data-type of
 * a field within a structure data-type. The field must already exist, except in the case of a
 * completely undefined structure. The data-type of the field is changed according to the user
 * selection.  If the size of the selected data-type is bigger, this can trigger other fields in
 * the structure to be removed and may change the size of the structure.  The modified data-type
 * is permanently committed to the program's database.
 */
public class RetypeFieldAction extends AbstractDecompilerAction {

	public RetypeFieldAction() {
		super("Retype Field");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeField"));
		setPopupMenuData(new MenuData(new String[] { "Retype Field" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			DataType dt = getCompositeDataType(tokenAtCursor);
			return (dt != null);
		}
		return false;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		Composite composite = getCompositeDataType(tokenAtCursor);
		RetypeFieldTask retypeTask;
		if (composite instanceof Structure) {
			retypeTask = new RetypeStructFieldTask(context.getTool(), context.getProgram(),
				context.getComponentProvider(), tokenAtCursor, composite);
		}
		else {
			retypeTask = new RetypeUnionFieldTask(context.getTool(), context.getProgram(),
				context.getComponentProvider(), tokenAtCursor, composite);
		}
		retypeTask.runTask();
	}
}
