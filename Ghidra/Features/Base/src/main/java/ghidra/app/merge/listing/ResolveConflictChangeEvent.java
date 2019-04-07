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

import javax.swing.event.ChangeEvent;

/**
 * Event that gets passed to a listener to indicate that a user changed 
 * one of the choices in the row of a table that is part of the 
 * VerticalChoicesPanel or VariousChoicesPanel.
 */
class ResolveConflictChangeEvent extends ChangeEvent {
    private final static long serialVersionUID = 1;
	int choice;
	int row;

	/**
	 * Creates a new event that gets passed to a listener to indicate that 
	 * a user changed one of the choices in the row of a table that is part 
	 * of the VerticalChoicesPanel or VariousChoicesPanel.
	 * @param source the component where the change happened.
	 * @param row the row where the user changed a choice
	 * @param choice the new choice value for the row
	 */
	ResolveConflictChangeEvent(Object source, int row, int choice) {
		super(source);
		this.row = row;
		this.choice = choice;
	}
	
	/**
	 * Returns the row where the change occurred.
	 */
	int getRow() {
		return row;
	}
	
	/**
	 * Returns the new choice value for the row.
	 */
	int getChoice() {
		return choice;
	}

}
