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
 * A ProjectedSequenceInfo object records two pieces of information: the index of a sequence in a database,
 * and the index in the sequence of the first character after the prefix sequence (see {@code ProjectedDatabase}
 */

public class ProjectedSequenceInfo {
	private int sequenceIndex;
	private int projectedIndex;

	/**
	 * Create a new {@link ProjectedSequenceInfo} object 
	 * @param sequenceIndex index of a sequence in the database
	 * @param projectedIndex index in the sequence of the first character after the the projection prefix
	 */
	public ProjectedSequenceInfo(int sequenceIndex, int projectedIndex) {
		this.sequenceIndex = sequenceIndex;
		this.projectedIndex = projectedIndex;
	}

	/**
	 * Get the sequence index
	 * @return sequence index
	 */
	public int getSequenceIndex() {
		return sequenceIndex;
	}

	/**
	 * Get the projected index
	 * @return projected index
	 */
	public int getProjectedIndex() {
		return projectedIndex;
	}
}
