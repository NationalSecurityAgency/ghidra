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
package ghidra.app.util.pdb.pdbapplicator;

/**
 * PDB Analyzer user algorithmic choice for performing object oriented class layout.
 * <p>
 * Actual algorithms determination is as follows:
 * {@link #MEMBERS_ONLY} is a fixed setting.  The others weigh the setting against the data
 * available in the class records.  They all start out as {@link #COMPLEX} but fall back to a
 * more simplistic layout when the data permits:
 * <p> {@link #SIMPLE_COMPLEX} can fall back to "simple" and
 * <p> {@link #BASIC_SIMPLE_COMPLEX} can fall back to "simple" or "basic"
 */
public enum ObjectOrientedClassLayout {
	MEMBERS_ONLY("Legacy"),
	BASIC_SIMPLE_COMPLEX("Complex with Basic Fallback"),
	SIMPLE_COMPLEX("Complex with Simple Fallback"),
	COMPLEX("Complex Always");

	private final String label;

	@Override
	public String toString() {
		return label;
	}

	private ObjectOrientedClassLayout(String label) {
		this.label = label;
	}

}
