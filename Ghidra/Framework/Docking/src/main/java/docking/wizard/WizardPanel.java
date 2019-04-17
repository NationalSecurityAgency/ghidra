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
package docking.wizard;

import ghidra.util.HelpLocation;

import java.awt.Component;

import javax.swing.JPanel;

/**
 * Interface to define methods for panels to be shown in the wizard dialog.
 */
public interface WizardPanel {
	/**
	 * Get the title for this panel.
	 * @return String title
	 */
	public String getTitle();
	/**
	 * Get the panel object
	 * @return JPanel panel
	 */
	public JPanel getPanel();
	/**
	 * Return true if the user entered valid information for this panel.
	 * @return boolean whether or not the info on the panel valid
	 */
	public boolean isValidInformation();
    /**
     * Initialize the panel as though this is the first time it is
     * being displayed.
     */
    public void initialize();
	/**
	 * Add a listener to this panel.
	 * @param l listener to add
	 */
	public void addWizardPanelListener(WizardPanelListener l);
	/**
	 * Remove the listener from this panel.
	 * @param l listener to remove
	 */
	public void removeWizardPanelListener(WizardPanelListener l);
    /**
     * Returns the help content location for this panel. 
     * 
     * @return String help location for this panel; return null if default help
     * location should be used.
     */
    public HelpLocation getHelpLocation();
    
    /**
     * Returns the component, if any, that should receive focus when this panel is shown.
     * @return the component, if any, that should receive focus when this panel is shown; null
     *         if no preferred focus component exists.
     */
    public Component getDefaultFocusComponent();
}
