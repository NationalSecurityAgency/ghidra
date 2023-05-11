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
package docking.framework;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import generic.application.GenericApplicationLayout;
import generic.theme.GThemeDefaults.Colors;
import ghidra.framework.Application;
import utility.application.ApplicationLayout;

/**
 * Splash screen window to display version information about the current release of
 * the Ghidra application. The window is displayed when Ghidra starts; when
 * initialization is complete, the splash screen is dismissed.
 */
public class AboutDialog extends DialogComponentProvider {

	public AboutDialog() {
		super(ApplicationInformationDisplayFactory.createAboutTitle(), true, false, true, false);
		addWorkPanel(createMainPanel());
		addOKButton();

		setRememberSize(false);
		setRememberLocation(false);

		setHelpLocation(ApplicationInformationDisplayFactory.createHelpLocation());

		// nothing in our window takes focus, so we have to do this in order to get the default
		// button to respond to key events properly
		setFocusComponent(okButton);
	}

	@Override
	protected void okCallback() {
		close();
	}

	/**
	 * Create the contents of the window.
	 */
	private JPanel createMainPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createRaisedBevelBorder());
		mainPanel.setBackground(Colors.BACKGROUND);
		mainPanel.add(createInfoComponent(), BorderLayout.CENTER);
		return mainPanel;
	}

	private JComponent createInfoComponent() {
		return ApplicationInformationDisplayFactory.createAboutComponent();
	}

	public static void main(String[] args) throws Exception {
		ApplicationLayout layout = new GenericApplicationLayout("About Dialog", "1.0");
		DockingApplicationConfiguration config = new DockingApplicationConfiguration();
		config.setShowSplashScreen(false);
		Application.initializeApplication(layout, config);
		DockingWindowManager.showDialog(null, new AboutDialog());
	}
}
