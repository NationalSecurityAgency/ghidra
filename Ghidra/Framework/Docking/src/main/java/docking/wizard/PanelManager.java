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

import java.awt.Dimension;

/**
 * Interface to define methods that control what panel is displayed in a
 * wizard.
 */
public interface PanelManager {
	/**
	 * Return true if the "finish" step can be completed. 
	 * @return boolean true if ok to finish
	 */
	public boolean canFinish();

	/**
	 * Return true if there is a "next" panel.
	 * @return boolean true means there is a next panel to display
	 */
	public boolean hasNextPanel();

	/**
	 * Return true if there is a "previous" panel.
	 * @return boolean true means there is a previous panel to display
	 */
	public boolean hasPreviousPanel();

	/**
	 * Get the next panel in the process.
	 * @return WizardPanel the next panel
	 * @throws IllegalPanelStateException if an IOException or other unexpected error occurs
	 */
	public WizardPanel getNextPanel() throws IllegalPanelStateException;

	/**
	 * Get the first panel in the process.
	 * @return WizardPanel the first panel
	 * @throws IllegalPanelStateException if an IOException or other unexpected error occurs 
	 */
	public WizardPanel getInitialPanel() throws IllegalPanelStateException;

	/**
	 * Get the previous panel in the process.
	 * @return WizardPanel the previous panel
	 * @throws IllegalPanelStateException if an IOException or other unexpected error occurs 
	 */
	public WizardPanel getPreviousPanel() throws IllegalPanelStateException;

	/**
	 * Get the status message for the current panel.
	 * @return String message to display;
	 *                may be null if there is no message that should be displayed
	 */
	public String getStatusMessage();

	/**
	 * Method called when the user wants to finish the process.
	 * @throws IllegalPanelStateException if an IOException or other unexpected error occurs
	 */
	public void finish() throws IllegalPanelStateException;

	/**
	 * Method called when the user wants to cancel the process.
	 */
	public void cancel();

	/**
	 * Set up the panel process.   This may also be called to clear the state of an existing panel, 
	 * such as when the overall wizard is finished.
	 */
	public void initialize();

	/**
	 * Get the size of the panels.
	 * @return Dimension size of the panel
	 */
	public Dimension getPanelSize();

	/**
	 * Set the wizard manager for this panel manager.
	 * @param wm wizard manager that calls the methods on this panel 
	 * manager
	 */
	public void setWizardManager(WizardManager wm);

	/**
	 * Get the wizard manager.
	 * @return WizardManager wizard manager for this panel manager
	 */
	public WizardManager getWizardManager();
}
