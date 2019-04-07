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
package ghidra.feature.vt.gui.actions;

/**
 * An enum to describe the available selection tracking states.  By default Ghidra tables will try 
 * to track the selected element, even if its row changes.  Some applications do not want this 
 * behavior.  As an example, some applications would rather that the selected row index not 
 * change as the table contents change.
 */
public enum TableSelectionTrackingState {

	/**
	 * Tracks selection for the user's selected row value (instead of the selected index).  This
	 * is useful when the row value changes position in the table due to sorting changes.
	 */
	MAINTAIN_SELECTED_ROW_VALUE,

	/**
	 * Tracks selection for the selected row (instead of the selected value).  This has the effect
	 * of always keeping the same row selected, even when the row value changes.
	 */
	MAINTAIN_SELECTED_ROW_INDEX,

	/**
	 * No selection tracking takes place.  When a selection is lost, the table will not try to
	 * restore it.
	 */
	NO_SELECTION_TRACKING;
}
