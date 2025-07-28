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
package ghidra.features.codecompare.decompile;

import docking.action.MenuData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionUtility;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Duo.Side;

/**
 * An action for transferring the full function signature between matched callee tokens
 */
public class ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction
		extends AbstractMatchedCalleeTokensAction {
	private PluginTool tool;
	public static final String ACTION_NAME =
		"Function Comparison Apply Callee Signature And Datatypes";

	/**
	 * Construtor
	 * @param diffPanel diff panel
	 * @param tool tool
	 */
	public ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction(
			DecompilerCodeComparisonPanel diffPanel, PluginTool tool) {
		super(ACTION_NAME, tool.getName(), diffPanel, true);
		this.tool = tool;

		MenuData menuData =
			new MenuData(new String[] { MENU_PARENT, "Callee Signature and Data Types" },
				null, MENU_GROUP);
		setPopupMenuData(menuData);
		setHelpLocation(new HelpLocation(HELP_TOPIC, getName()));
	}

	@Override
	protected void doCalleeActionPerformed(Function leftFunction, Function rightFunction) {

		Side activeSide = diffPanel.getActiveSide();

		Function activeFunction = activeSide == Side.LEFT ? leftFunction : rightFunction;
		Function otherFunction = activeSide == Side.LEFT ? rightFunction : leftFunction;

		Program activeProgram = activeFunction.getProgram();

		try {
			activeProgram.withTransaction(
				"Code Comparison Transfer Callee Signature and Data Types",
				() -> FunctionUtility.applySignature(activeFunction, otherFunction, false, null));
		}
		catch (Exception e) {
			Msg.showError(this, tool.getToolFrame(),
				"Failed to Apply Callee Signature and Data Types", e.getMessage());
		}
	}
}
