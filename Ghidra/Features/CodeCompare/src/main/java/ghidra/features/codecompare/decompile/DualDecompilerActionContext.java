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

import java.awt.Component;
import java.util.Iterator;
import java.util.List;

import docking.ComponentProvider;
import ghidra.app.context.RestrictedAddressSetContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.features.base.codecompare.panel.CodeComparisonActionContext;
import ghidra.features.codecompare.graphanalysis.TokenBin;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.datastruct.Duo.Side;

/**
 * Action context for a dual decompiler panel.
 */
public class DualDecompilerActionContext extends CodeComparisonActionContext
		implements RestrictedAddressSetContext {

	private DecompilerCodeComparisonPanel decompilerComparisonPanel = null;
	private TokenPair tokenPair;
	private boolean overrideReadOnly = false;

	/**
	 * Creates an action context for a dual decompiler panel.
	 * @param provider the provider for this context
	 * @param panel the DecompilerComparisonPanel
	 * @param source the source of the action
	 */
	public DualDecompilerActionContext(ComponentProvider provider,
			DecompilerCodeComparisonPanel panel, Component source) {
		super(provider, panel, source);
		decompilerComparisonPanel = panel;
		tokenPair = computeTokenPair();
	}

	private TokenPair computeTokenPair() {
		DecompilerPanel focusedPanel =
			decompilerComparisonPanel.getActiveDisplay().getDecompilerPanel();

		if (!(focusedPanel.getCurrentLocation() instanceof DecompilerLocation focusedLocation)) {
			return null;
		}

		ClangToken focusedToken = focusedLocation.getToken();
		if (focusedToken == null) {
			return null;
		}
		List<TokenBin> tokenBin = decompilerComparisonPanel.getHighBins();
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
				return decompilerComparisonPanel.getActiveSide() == LEFT
						? new TokenPair(focusedToken, currentMatch)
						: new TokenPair(currentMatch, focusedToken);
			}
		}
		return null;
	}

	/**
	 * Returns the {@link DecompilerCodeComparisonPanel} that generated this context
	 * @return the decompiler comparison panel that generated this context
	 */
	@Override
	public DecompilerCodeComparisonPanel getCodeComparisonPanel() {
		return decompilerComparisonPanel;
	}

	/**
	 * Returns the {@link HighFunction} being viewed on the given side by the decompiler panel that 
	 * generated this context
	 * @param side the side of the comparison to retrieve the high function for
	 * @return the high function on the given side of the comparison panel that generated this 
	 * context
	 */
	public HighFunction getHighFunction(Side side) {
		return decompilerComparisonPanel.getDecompilerPanel(side).getController().getHighFunction();
	}

	/**
	 * Returns the {@link TokenPair} currently selected in the diff view, if any.
	 * @return the token pair selected when this context was generated
	 */
	public TokenPair getTokenPair() {
		return tokenPair;
	}

	/**
	 * Set whether this context will bypass a check to the actual state of the active program
	 * when resolving {@link #isActiveProgramReadOnly}. Used by tests.
	 * @param overrideReadOnly true if this context should bypass an 
	 * {@link #isActiveProgramReadOnly} by always returning false
	 */
	void setOverrideReadOnly(boolean overrideReadOnly) {
		this.overrideReadOnly = overrideReadOnly;
	}

	/**
	 * Check if the program associated with the focused window in the dual decompiler view is
	 * read only. Always false if read only override was set to true with a call to 
	 * {@link #setOverrideReadOnly}
	 * @return true if the active program is read only, always false if override is set to true
	 */
	public boolean isActiveProgramReadOnly() {
		if (overrideReadOnly) {
			return false;
		}

		Program activeProgram =
			decompilerComparisonPanel.getProgram(decompilerComparisonPanel.getActiveSide());

		if (activeProgram == null) {
			return true;
		}

		return activeProgram.getDomainFile().isReadOnly();
	}

}
