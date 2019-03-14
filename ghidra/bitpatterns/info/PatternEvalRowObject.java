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
package ghidra.bitpatterns.info;

import ghidra.program.model.address.*;

/**
 * Objects in this class represent one row in the Pattern Evaluation table.
 */
public class PatternEvalRowObject {

	private PatternMatchType matchType;
	private AddressSetView matchedSet;
	private String patternString;
	private Address matchedAddress;
	private int postBits;
	private int totalBits;

	/**
	 * Creates a row object for the Pattern Evaluation table
	 * @param matchType type of the match
	 * @param matchedSet bytes of the program containing the match
	 * @param patternString String representation of the pattern
	 * @param matchedAddress address of the match
	 * @param postBits number of fixed bits in the pattern after the function start
	 * @param totalBits total number of fixed bits in the pattern
	 */
	public PatternEvalRowObject(PatternMatchType matchType, AddressSetView matchedSet,
			String patternString, Address matchedAddress, int postBits, int totalBits) {
		this.matchType = matchType;
		this.matchedSet = matchedSet;
		this.patternString = patternString;
		this.matchedAddress = matchedAddress;
		this.postBits = postBits;
		this.totalBits = totalBits;
	}

	/**
	 * Returns the type of the match.
	 * @return match type
	 */
	public PatternMatchType getMatchType() {
		return matchType;
	}

	/**
	 * Returns an {@link AddressSet} where the match occurs
	 * @return matching AddressSet
	 */
	public AddressSetView getMatchedSet() {
		return matchedSet;
	}

	/**
	 * Returns a {@code} String representation of the pattern
	 * @return pattern as string
	 */
	public String getPatternString() {
		return patternString;
	}

	/**
	 * Returns the addresses where the match occurs
	 * @return address of match
	 */
	public Address getMatchedAddress() {
		return matchedAddress;
	}

	/**
	 * Returns the number fixed bits of the pattern after the function start 
	 * @return number of postbits
	 */
	public int getPostBits() {
		return postBits;
	}

	/**
	 * Returns the total number of fixed bits of the pattern
	 * @return
	 */
	public int getTotalBits() {
		return totalBits;
	}

}
