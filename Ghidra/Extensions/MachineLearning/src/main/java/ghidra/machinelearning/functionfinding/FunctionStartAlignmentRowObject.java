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
package ghidra.machinelearning.functionfinding;

/**
 * A member of this class is a row in a {@link FunctionStartAlignmentTableModel}
 */
public class FunctionStartAlignmentRowObject {

	private long remainder;
	private long numFuncs;

	/**
	 * Creates a row showing how many functions whose entry points have
	 * a remainder of {@code remainder} when divided by the alignment modulus.
	 * @param remainder remainder after division by alignment modulus
	 * @param numFuncs number of functions 
	 */
	public FunctionStartAlignmentRowObject(long remainder, long numFuncs) {
		this.remainder = remainder;
		this.numFuncs = numFuncs;
	}

	/**
	 * Returns the remainder
	 * @return remainder
	 */
	public long getRemainder() {
		return remainder;
	}

	/**
	 * Returns the number of functions	
	 * @return num funcs
	 */
	public long getNumFuncs() {
		return numFuncs;
	}

}
