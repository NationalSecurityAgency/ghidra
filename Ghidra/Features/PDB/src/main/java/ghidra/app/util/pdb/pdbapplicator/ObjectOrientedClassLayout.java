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
 * <p> {@link #MEMBERS_ONLY} is a the legacy output that only shows members of the current class.
 * <p> {@link #CLASS_HIERARCHY} provides a nested layout more suitable for understanding
 * the composition of classes from base classes and members from the Structure Editor perspective.
 */
public enum ObjectOrientedClassLayout {
	/**
	 * Processes members of the current class only; legacy solution
	 */
	MEMBERS_ONLY("No C++ Hierarchy (Legacy)"),
	/**
	 * Include base class hierarchies and other C++-isms into a class layout that is suited for
	 * understanding the hierarchies and components from the Structure Editor perspective
	 */
	CLASS_HIERARCHY("Class Hierarchy (Experimental)");

	private final String label;

	@Override
	public String toString() {
		return label;
	}

	private ObjectOrientedClassLayout(String label) {
		this.label = label;
	}

}
