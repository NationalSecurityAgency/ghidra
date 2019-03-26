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
package docking.action;

/**
 * Interface for actions that have a toggle state
 *
 */
public interface ToggleDockingActionIf extends DockingActionIf {
	public static final String SELECTED_STATE_PROPERTY = "selectState";
	
	/**
	 * Returns true if the toggle state for this action is current selected.
	 * @return true if the toggle state for this action is current selected.
	 */
	public abstract boolean isSelected();
	
	/**
	 * Sets the toggle state for this action.
	 * @param newValue the new toggle state.
	 */
	public abstract void setSelected(boolean newValue);
}
