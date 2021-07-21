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

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.HelpLocation;
import java.awt.event.KeyEvent;

public class SetEquateAction extends ConvertConstantAction {

	public SetEquateAction(DecompilePlugin plugin) {
		super(plugin, "Set Equate", EquateSymbol.FORMAT_DEFAULT);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionSetEquate"));
		setPopupMenuData(new MenuData(new String[] { "Set Equate..." }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_E, 0));
	}

	@Override
	public String getMenuPrefix() {
		return null;		// Menu isn't tailored for this action
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned) {
		return null;		// Menu isn't tailored for this action
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		if (program == null) {
			return null;
		}
		Scalar scalar = new Scalar(size * 8, value, isSigned);
		SetEquateDialog dialog = new SetEquateDialog(plugin.getTool(), program, scalar);
		dialog.disableHasSelection();
		int res = dialog.showSetDialog();
		String name = null;
		if (res != SetEquateDialog.CANCELED) {
			name = dialog.getEquateName();
		}
		dialog.dispose();
		return name;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		ConvertConstantTask task = establishTask(context, false);
		return (task != null);
	}
}
