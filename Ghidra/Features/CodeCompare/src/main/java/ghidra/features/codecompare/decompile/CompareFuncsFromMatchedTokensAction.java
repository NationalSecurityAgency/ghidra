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
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * An action for bringing up a side-by-side function comparison of callees with matching 
 * tokens.
 */
public class CompareFuncsFromMatchedTokensAction extends AbstractMatchedCalleeTokensAction {
	private PluginTool tool;
	private static final String ACTION_NAME = "Compare Matching Callees";

	/**
	 * Constructor
	 * @param diffPanel diff Panel
	 * @param tool tool
	 */
	public CompareFuncsFromMatchedTokensAction(DecompilerCodeComparisonPanel diffPanel,
			PluginTool tool) {
		super(ACTION_NAME, tool.getName(), diffPanel, false);
		this.tool = tool;

		MenuData menuData = new MenuData(new String[] { ACTION_NAME }, null, MENU_GROUP);
		setPopupMenuData(menuData);
		setHelpLocation(new HelpLocation(HELP_TOPIC, "Compare Matching Callees"));
	}

	@Override
	protected void doCalleeActionPerformed(Function leftFunction, Function rightFunction) {
		FunctionComparisonService service = tool.getService(FunctionComparisonService.class);
		if (service == null) {
			Msg.error(this, "Function Comparison Service not found!");
			return;
		}
		service.createComparison(leftFunction, rightFunction);
	}

}
