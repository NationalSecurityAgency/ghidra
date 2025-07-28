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

import static ghidra.util.datastruct.Duo.Side.*;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * Subclass of {@link AbstractMatchedTokensAction} for actions in a 
 * {@link DecompilerCodeComparisonPanel} that are available only when the matched tokens are
 * function calls
 */
public abstract class AbstractMatchedCalleeTokensAction extends AbstractMatchedTokensAction {
	protected static final String MENU_GROUP = "A2_ApplyCallee";

	/**
	 * Constructor
	 * 
	 * @param actionName name of action
	 * @param owner owner of action
	 * @param diffPanel diff panel containing action
	 * @param disableOnReadOnly if true, action will be disabled for read-only programs
	 */
	public AbstractMatchedCalleeTokensAction(String actionName, String owner,
			DecompilerCodeComparisonPanel diffPanel, boolean disableOnReadOnly) {
		super(actionName, owner, diffPanel, disableOnReadOnly);
	}

	@Override
	protected boolean isEnabledForDualDecompilerContext(DualDecompilerActionContext context) {
		TokenPair tokenPair = context.getTokenPair();

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
	public void dualDecompilerActionPerformed(DualDecompilerActionContext context) {
		DecompilerCodeComparisonPanel decompPanel = context.getCodeComparisonPanel();

		TokenPair currentPair = context.getTokenPair();

		ClangFuncNameToken leftFuncToken = (ClangFuncNameToken) currentPair.leftToken();
		ClangFuncNameToken rightFuncToken = (ClangFuncNameToken) currentPair.rightToken();

		Function leftFunction = getFuncFromToken(leftFuncToken, decompPanel.getProgram(LEFT));
		Function rightFunction = getFuncFromToken(rightFuncToken, decompPanel.getProgram(RIGHT));
		if (leftFunction == null || rightFunction == null) {
			return;
		}

		doCalleeActionPerformed(leftFunction, rightFunction);
	}

	/**
	 * Once function objects have been recovered from the callee tokens, perform an action
	 * @param leftFunction the callee function on the left side of the decompiler diff panel
	 * @param rightFunction the callee function on the right side of the decompiler diff panel
	 */
	protected abstract void doCalleeActionPerformed(Function leftFunction, Function rightFunction);

	private Function getFuncFromToken(ClangFuncNameToken funcToken, Program program) {
		Address callTarget = funcToken.getPcodeOp().getInput(0).getAddress();
		Function func = program.getFunctionManager().getFunctionAt(callTarget);
		if (func == null) {
			Msg.showWarn(this, null, "Unable to Compare Callees",
				"Can't compare callees - null Function for " + funcToken.getText());
			return null;
		}
		if (func.isExternal()) {
			Msg.showWarn(this, null, "Unable to Compare Callees",
				"Can't compare callees - " + func.getName() + " is external");
			return null;
		}
		if (!func.isThunk()) {
			return func;
		}
		func = func.getThunkedFunction(true);
		if (func.isExternal()) {
			Msg.showWarn(this, null, "Unable to Compare",
				"Can't compare callees - " + func.getName() + " is external");
			return null;
		}
		return func;

	}
}
