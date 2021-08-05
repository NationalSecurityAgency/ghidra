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
package docking.wizard;

public interface MagePanel<T> extends WizardPanel {
	public void addDependencies(WizardState<T> state);

	/**
	 * Enter and leave panel for pretend; take your state from the state object and then add
	 * whatever state you need into it to pretend finish the wizard (if possible).  Return
	 * whether you must, can, or should not be displayed.
	 * @param state the state object
	 * @return displayability
	 */
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(WizardState<T> state);

	/**
	 * Enter panel for real; take your state from the state object and then
	 * populate your external state accordingly. 
	 * @param state the state object
	 * @throws IllegalPanelStateException indicates that something bad has happened and we should
	 * return to the very first panel - unless we are the first panel in which case we
	 * should abort the wizard.
	 */
	public void enterPanel(WizardState<T> state) throws IllegalPanelStateException;

	/**
	 * Leave panel for real; inject your external state into the state object.
	 * @param state the state object
	 */
	public void leavePanel(WizardState<T> state);

	/**
	 * Updates the state object, being passed as a parameter, with the current state information 
	 * from this panel. Only state information that the panel is intended to set should be modified 
	 * within the state object by this method. For example, a summary panel might display state 
	 * information, but doesn't set it and therefore wouldn't change it in the state object.
	 * @param state the state object to update
	 */
	public void updateStateObjectWithPanelInfo(WizardState<T> state);

	/**
	 * Called when the wizard is cancelled or otherwise finished being shown
	 */
	public void dispose();
}
