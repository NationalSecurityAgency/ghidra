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
package ghidra.codecompare.graphanalysis;

import java.util.*;

import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;

/**
 * An iterable list of Decompiler tokens {@link ClangToken} in one window that is paired with a
 * list in another window. The matching TokenBin, if it exists, is obtained by calling
 * getMatch(). This container is constructed and populated only by {@link Pinning}.
 */
public class TokenBin implements Iterable<ClangToken> {
	private ArrayList<ClangToken> bin;		// The list of tokens in this bin
	private HighFunction highFunction;		// The function owning the tokens 
	TokenBin sidekick;						// The bin (from the other window) matching this

	/**
	 * Construct an (initially empty) token bin.
	 * @param highFunction is the function the bin is associated with
	 */
	TokenBin(HighFunction highFunction) {
		this.bin = new ArrayList<>();
		this.highFunction = highFunction;
		this.sidekick = null;
	}

	/**
	 * @return the HighFunction owning the tokens in this bin
	 */
	public HighFunction getHighFunction() {
		return highFunction;
	}

	/**
	 * @return the TokenBin paired with this
	 */
	public TokenBin getMatch() {
		return sidekick;
	}

	/**
	 * Get the i-th token in this bin
	 * @param i is the index of the token
	 * @return the selected token
	 */
	public ClangToken get(int i) {
		return bin.get(i);
	}

	/**
	 * @return the number of tokens in this bin
	 */
	public int size() {
		return bin.size();
	}

	@Override
	public Iterator<ClangToken> iterator() {
		return bin.iterator();
	}

	/**
	 * Add a new token to this bin.
	 * @param newToken is the token to add
	 */
	void add(ClangToken newToken) {
		// Check to make sure we're in the right function.
		HighFunction tokenHighFunction = newToken.getClangFunction().getHighFunction();
		if (!highFunction.equals(tokenHighFunction)) {
			Msg.warn(this,
				"ERROR: Trying to ADD token '" + newToken.getText() + "' to incorrect TokenBin.");
			return;
		}
		bin.add(newToken);		// Add token to the list
	}

	/**
	 * From a list of TokenBins, find the (first) one containing a particular ClangToken
	 * @param highBins is the list of bins
	 * @param myToken is the ClangToken to find
	 * @return the first bin containing the token, or null
	 */
	public static TokenBin getBinContainingToken(List<TokenBin> highBins, ClangToken myToken) {
		for (TokenBin bin : highBins) {
			for (ClangToken token : bin.bin) {
				if (myToken == token) {
					return bin;
				}
			}
		}
		return null;
	}
}
