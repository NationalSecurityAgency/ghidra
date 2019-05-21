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
package ghidra.framework.options;

import java.awt.Color;
import java.beans.PropertyEditorSupport;

import javax.swing.JComponent;
import javax.swing.JLabel;

public class ErrorPropertyEditor extends PropertyEditorSupport {
	private JLabel errorLabel;
	private Object editorValue;

	public ErrorPropertyEditor(String errorMessage, Object value) {
		editorValue = value;
		String message = errorMessage;
		if (editorValue != null) {
			message += " - value: " + value.toString();
		}

		// Use native java JLabel because we can't use docking widgets here
		errorLabel = new JLabel(message);
		errorLabel.setForeground(Color.RED);
		errorLabel.putClientProperty("html.disable", true);
	}

	@Override
	public JComponent getCustomEditor() {
		return errorLabel;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}
}
