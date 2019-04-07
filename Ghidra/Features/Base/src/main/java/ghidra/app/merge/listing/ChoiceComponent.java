/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge.listing;

import java.awt.LayoutManager;

import javax.swing.JPanel;

/**
 * Abstract class for a GUI panel that allows the user to select choices for 
 * resolving conflicts.
 */
public abstract class ChoiceComponent extends JPanel {

	public ChoiceComponent() {
		super();
	}

	public ChoiceComponent(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
	}

	public ChoiceComponent(LayoutManager layout, boolean isDoubleBuffered) {
		super(layout, isDoubleBuffered);
	}

	public ChoiceComponent(LayoutManager layout) {
		super(layout);
	}

	/**
	 * Returns whether or not all of the choices (conflicts) have been resolved
	 * by the user making selections.
	 * @return true if all conflicts are resolved.
	 */
	public abstract boolean allChoicesAreResolved();

	/**
	 * Returns the number of conflicts that have currently been resolved in this GUI component.
	 * @return the number resolved.
	 */
	public abstract int getNumConflictsResolved();

	/**
	 * Returns whether or not all of the choices (conflicts) have been resolved
	 * by the user making selections and the user made the same choice for all the conflicts.
	 * @return true if all conflicts are resolved the same.
	 */
	public abstract boolean allChoicesAreSame();

}
