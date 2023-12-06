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
package ghidra.codecompare;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.component.DecompilerCodeComparisonPanel;
import ghidra.app.decompiler.component.DualDecompilerActionContext;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * An action for bringing up a side-by-side function comparison of callees with matching 
 * tokens.
 */
public class CompareFuncsFromMatchedTokensAction extends AbstractMatchedTokensAction {
	private PluginTool tool;
	private static final String ACTION_NAME = "Compare Matching Callees";
	private static final String MENU_GROUP = "A1_Compare";
	private static final String HELP_TOPIC = "FunctionComparison";

	/**
	 * Constructor
	 * @param diffPanel diff Panel
	 * @param tool tool
	 */
	public CompareFuncsFromMatchedTokensAction(DecompilerDiffCodeComparisonPanel diffPanel,
			PluginTool tool) {
		super(ACTION_NAME, tool.getName(), diffPanel, false);
		this.tool = tool;
		FunctionComparisonService service = tool.getService(FunctionComparisonService.class);
		if (service != null) {
			MenuData menuData = new MenuData(new String[] { ACTION_NAME }, null, MENU_GROUP);
			setPopupMenuData(menuData);
			setEnabled(true);
			setHelpLocation(new HelpLocation(HELP_TOPIC, "Compare Matching Callees"));
		}
	}

	@Override
	protected boolean enabledForTokens(TokenPair tokenPair) {
		if (tokenPair == null) {
			return false;
		}
		if (tokenPair.leftToken() == null || tokenPair.rightToken() == null) {
			return false;
		}
		PcodeOp leftOp = tokenPair.leftToken().getPcodeOp();
		PcodeOp rightOp = tokenPair.rightToken().getPcodeOp();
		if (leftOp == null || rightOp == null) {
			return false;
		}
		if (leftOp.getOpcode() != PcodeOp.CALL || rightOp.getOpcode() != PcodeOp.CALL) {
			return false;
		}
		return (tokenPair.leftToken() instanceof ClangFuncNameToken) &&
			(tokenPair.rightToken() instanceof ClangFuncNameToken);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof DualDecompilerActionContext compareContext)) {
			return;
		}

		if (!(compareContext
				.getCodeComparisonPanel() instanceof DecompilerCodeComparisonPanel decompPanel)) {
			return;
		}

		@SuppressWarnings("unchecked")
		TokenPair currentPair = getCurrentTokenPair(decompPanel);
		if (currentPair == null || currentPair.leftToken() == null ||
			currentPair.rightToken() == null) {
			return;
		}
		FunctionComparisonService service = tool.getService(FunctionComparisonService.class);
		if (service == null) {
			Msg.error(this, "Function Comparison Service not found!");
			return;
		}
		FunctionComparisonProvider comparisonProvider = service.createFunctionComparisonProvider();
		comparisonProvider.removeAddFunctionsAction();

		ClangFuncNameToken leftFuncToken = (ClangFuncNameToken) currentPair.leftToken();
		ClangFuncNameToken rightFuncToken = (ClangFuncNameToken) currentPair.rightToken();

		Function leftFunction = getFuncFromToken(leftFuncToken, decompPanel.getLeftProgram());
		Function rightFunction = getFuncFromToken(rightFuncToken, decompPanel.getRightProgram());

		if (leftFunction == null || rightFunction == null) {
			return;
		}

		comparisonProvider.getModel().compareFunctions(leftFunction, rightFunction);

	}

	private Function getFuncFromToken(ClangFuncNameToken funcToken, Program program) {
		Address callTarget = funcToken.getPcodeOp().getInput(0).getAddress();
		return program.getFunctionManager().getFunctionAt(callTarget);
	}

}
