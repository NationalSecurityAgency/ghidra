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
package ghidra.bitpatterns.gui;

import java.awt.BorderLayout;

import javax.swing.*;

/**
 * 
 * This class is used to construct the "Context Register Information" panel
 *
 */
public class ContextRegisterPanelBuilder {

	private static final String DEFAULT = "No context register information";
	private JTextArea contextRegisterInfoField;
	private String message;

	/**
	 * Creates an object used to build the panel displaying the context register extent
	 * @param contextRegisterInfo string representation of context register extent
	 */
	public ContextRegisterPanelBuilder(String contextRegisterInfo) {
		if ((contextRegisterInfo == null) || (contextRegisterInfo.equals(""))) {
			message = DEFAULT;
		}
		else {
			message = contextRegisterInfo;
		}
	}

	/**
	 * Builds panel to display the context register extent
	 * @return panel
	 */
	public JPanel buildContextRegisterPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		contextRegisterInfoField = new JTextArea();
		contextRegisterInfoField.setText(message);
		contextRegisterInfoField.setEditable(false);
		panel.add(contextRegisterInfoField);
		return panel;
	}

}
