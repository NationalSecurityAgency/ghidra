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
package ghidra.closedpatternmining;

/**
 * 
 * Objects of this class store information to control runs of the closed sequence pattern mining 
 * algorithm.
 *
 */

public class SequenceMiningParams {

	private double minPercentage;
	private int requiredBitsOfCheck;
	private boolean useBinary;

	/**
	 * Create a new {@link SequenceMiningParams} object 
	 * @param minPercentage percentage of sequences in a database that must contain a pattern for the pattern
	 * to be deemed "frequent"
	 * @param minBitsOfCheck minimum number of non-ditted bits a pattern must contain before it is displayed to
	 * the user
	 * @param useBinary if true, sequences are treated as binary strings.  Otherwise they are treated as sequences
	 * of characters (nibbles)
	 */
	public SequenceMiningParams(double minPercentage, int minBitsOfCheck, boolean useBinary) {
		this.minPercentage = minPercentage;
		this.requiredBitsOfCheck = minBitsOfCheck;
		this.useBinary = useBinary;
	}

	/**
	 * Returns the percentage of sequences in a database that must contain a pattern for the pattern to count as "frequent"
	 * @return percentage
	 */
	public double getMinPercentage() {
		return minPercentage;
	}

	/**
	 * Returns the minimum number of fixed bits a pattern must contain before it is displayed to the user
	 * @return minimum number of fixed bits
	 */
	public int getRequiredBitsOfCheck() {
		return requiredBitsOfCheck;
	}

	/**
	 * Returns a boolean value determining whether to treat sequences as binary strings (true) or character strings (false)
	 * @return whether to treat sequences as binary
	 */
	public boolean getUseBinary() {
		return useBinary;
	}

}
