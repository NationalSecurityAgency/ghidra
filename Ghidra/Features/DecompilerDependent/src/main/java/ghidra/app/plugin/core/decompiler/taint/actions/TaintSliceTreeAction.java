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
package ghidra.app.plugin.core.decompiler.taint.actions;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Triggered by right-click on a token in the decompiler window.
 * 
 * Action triggered from a specific token in the decompiler window to mark a variable as a
 * source or sink and generate the requisite query. Legal tokens to select include:
 * <ul><li>
 * An input parameter,
 * </li><li>
 * A stack variable, 
 * </li><li>
 * A variable associated with a register, or 
 * </li><li>
 * A "dynamic" variable. 
 * </li></ul>
 */
public class TaintSliceTreeAction extends TaintAbstractDecompilerAction {

	private TaintPlugin plugin;

	public TaintSliceTreeAction(TaintPlugin plugin, TaintState state) {
		super("Show Slice Tree");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintSliceTree"));
		setPopupMenuData(new MenuData(new String[] { "Taint", "Slice Tree" }, "Decompile"));
		setDescription(
			"Shows the Taint Slice Trees window for the item under the cursor in the decompilation window.  The new window will not change along with the Listing cursor.");
		this.plugin = plugin;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Msg.info(this, "TaintSliceTreeAction action performed: " + context.toString());
		Program program = context.getProgram();
		if (program == null) {
			return;
		}
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighVariable highVariable = tokenAtCursor.getHighVariable();
		String hv = highVariable == null ? "HV NULL" : highVariable.toString();

		Msg.info(this, "TaintSliceTreeAction action performed.\n" +
			"\tProgram: " + program.toString() + "\n" +
			"\tClangToken: " + tokenAtCursor.toString() + "\n" +
			"\tHighVariable: " + hv);

		if (highVariable != null) {
			// TODO This will need the sarif dataframe with only the path information.
			plugin.showOrCreateNewSliceTree(program, tokenAtCursor, highVariable);
		}
	}
}
