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

import java.util.Iterator;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.decompiler.component.*;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.program.model.listing.Program;

/**
 * This is a base class for actions in a {@link DecompilerDiffCodeComparisonPanel}
 */
public abstract class AbstractMatchedTokensAction extends DockingAction {

	protected DecompilerDiffCodeComparisonPanel diffPanel;
	protected boolean disableOnReadOnly;

	/**
	 * Constructor
	 * 
	 * @param actionName name of action
	 * @param owner owner of action
	 * @param diffPanel diff panel containing action
	 * @param disableOnReadOnly if true, action will be disabled for read-only programs
	 */
	public AbstractMatchedTokensAction(String actionName, String owner,
			DecompilerDiffCodeComparisonPanel diffPanel, boolean disableOnReadOnly) {
		super(actionName, owner);
		this.diffPanel = diffPanel;
		this.disableOnReadOnly = disableOnReadOnly;
	}

	/**
	 * Determines whether the action should be enable for a pair of
	 * matching tokens. 
	 * 
	 * @param tokenPair tokens
	 * @return true if action should be enabled
	 */
	protected abstract boolean enabledForTokens(TokenPair tokenPair);

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DualDecompilerActionContext compareContext)) {
			return false;
		}
		if (!(compareContext
				.getCodeComparisonPanel() instanceof DecompilerCodeComparisonPanel decompPanel)) {
			return false;
		}

		if (disableOnReadOnly) {
			//get the program corresponding to the panel with focus
			Program program = decompPanel.getLeftProgram();
			if (program == null) {
				return false; //panel initializing; don't enable action
			}
			if (!decompPanel.leftPanelHasFocus()) {
				program = decompPanel.getRightProgram();
			}
			if (!program.canSave()) {
				return false;  //program is read-only, don't enable action
			}
		}

		@SuppressWarnings("unchecked")
		TokenPair currentPair = getCurrentTokenPair(decompPanel);
		return enabledForTokens(currentPair);

	}

	/**
	 * Returns a {@link TokenPair} consisting of the token under the cursor in the focused
	 * decompiler panel and its counterpart in the other panel. 
	 *
	 * @param decompPanel decomp panel
	 * @return matching tokens (or null if no match)
	 */
	protected TokenPair getCurrentTokenPair(
			DecompilerCodeComparisonPanel<? extends DualDecompilerFieldPanelCoordinator> decompPanel) {

		DecompilerPanel focusedPanel = decompPanel.getFocusedDecompilerPanel().getDecompilerPanel();

		if (!(focusedPanel.getCurrentLocation() instanceof DecompilerLocation focusedLocation)) {
			return null;
		}

		ClangToken focusedToken = focusedLocation.getToken();
		if (focusedToken == null) {
			return null;
		}
		List<TokenBin> tokenBin = diffPanel.getHighBins();
		if (tokenBin == null) {
			return null;
		}
		TokenBin containingBin = TokenBin.getBinContainingToken(tokenBin, focusedToken);
		if (containingBin == null) {
			return null;
		}
		TokenBin matchedBin = containingBin.getMatch();
		if (matchedBin == null) {
			return null;
		}
		//loop over the tokens in the matching bin and return the first one in the same
		//class as focusedToken
		Iterator<ClangToken> tokenIter = matchedBin.iterator();
		while (tokenIter.hasNext()) {
			ClangToken currentMatch = tokenIter.next();
			if (currentMatch.getClass().equals(focusedToken.getClass())) {
				return decompPanel.leftPanelHasFocus() ? new TokenPair(focusedToken, currentMatch)
						: new TokenPair(currentMatch, focusedToken);
			}
		}
		return null;
	}

}
