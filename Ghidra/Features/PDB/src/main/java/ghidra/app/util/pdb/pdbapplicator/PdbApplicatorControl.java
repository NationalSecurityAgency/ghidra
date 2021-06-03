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
 * PDB Applicator control for actions performed.  Used by {@link PdbApplicatorOptions}
 */
public enum PdbApplicatorControl {
	ALL("Process All"),
	DATA_TYPES_ONLY("Data Types Only"),
	PUBLIC_SYMBOLS_ONLY("Public Symbols Only");

	private final String label;

	@Override
	public String toString() {
		return label;
	}

	private PdbApplicatorControl(String label) {
		this.label = label;
	}

}
