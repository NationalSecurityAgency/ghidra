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
package ghidra.app.script;

import java.awt.Component;
import java.awt.GridLayout;
import java.io.File;
import java.util.HashMap;

import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;

public class GatherParamPanel extends JPanel {
	private static final long serialVersionUID = 1L;

	public static final int STRING = 0;
	public static final int FILE = 1;
	public static final int DIRECTORY = 2;
	public static final int ADDRESS = 3;
	public static final int INTEGER = 4;
	public static final int LANGUAGE = 5;

	private GhidraState state;
	private HashMap<String, ParamComponent> parameters;
	private boolean shown;

	public GatherParamPanel(GhidraState state) {
		this.state = state;
		setLayout(new GridLayout(0, 2));
		parameters = new HashMap<>();
		shown = false;
	}

	public ParamComponent getParameter(String key) {
		return parameters.get(key);
	}

	public void clearParameters() {
		parameters.clear();
		removeAll();
	}

	public void addParameterRegardless(String key, String label, int type, Object defaultValue) {
		Component displayComponent = null;
		if (type == FILE || type == DIRECTORY) {
			String titleString = null;
			if (type == DIRECTORY) {
				titleString = "SELECT DIRECTORY";
			}
			else {
				titleString = "SELECT FILE";
			}
			GhidraFileChooserPanel panel = new GhidraFileChooserPanel(titleString,
				"Recipe.fileChooser", "", true, GhidraFileChooserPanel.INPUT_MODE);
			if (type == DIRECTORY) {
				panel.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			}
			panel.setFileName(defaultValue.toString());
			parameters.put(key, new ParamComponent(panel, type));
			displayComponent = panel;
		}
		else if (type == ADDRESS) {
			AddressInput addressInput = new AddressInput();
			if (state.getCurrentProgram() != null) {
				addressInput.setAddressFactory(state.getCurrentProgram().getAddressFactory());
			}
			addressInput.selectDefaultAddressSpace();
			addressInput.select();
			if (defaultValue != null) {
				addressInput.setValue(defaultValue.toString());
			}
			displayComponent = addressInput;
			parameters.put(key, new ParamComponent(displayComponent, type));
		}
		else {
			JTextField textField = new JTextField();
			if (defaultValue != null) {
				textField.setText(defaultValue.toString());
			}
			displayComponent = textField;
			parameters.put(key, new ParamComponent(displayComponent, type));
		}
		add(new GLabel(label));
		add(displayComponent);
		shown = false;
	}

	public void addParameter(String key, String label, int type, Object defaultValue) {
		if (parameters.containsKey(key) || state.getEnvironmentVar(key) != null) {
			return;
		}
		addParameterRegardless(key, label, type, defaultValue);
	}

	public void setParamsInState() {
		for (String string2 : parameters.keySet()) {
			String key = string2.toString();
			ParamComponent pc = parameters.get(key);
			switch (pc.getType()) {
				case ADDRESS:
					if (state.getCurrentProgram() != null) {
						AddressInput addressInput = (AddressInput) pc.getDisplayComponent();
						state.addEnvironmentVar(key, addressInput.getAddress());
					}
					else {
						AddressInput addressInput = (AddressInput) pc.getDisplayComponent();
						state.addEnvironmentVar(key, addressInput.getValue().toString());
					}
					break;
				case FILE:
				case DIRECTORY:
					GhidraFileChooserPanel gfcp = (GhidraFileChooserPanel) pc.getDisplayComponent();
					state.addEnvironmentVar(key, new File(gfcp.getFileName()));
					break;
				case INTEGER:
					JTextField iTextField = (JTextField) pc.getDisplayComponent();
					int val = Integer.parseInt(iTextField.getText());
					state.addEnvironmentVar(key, val);
					break;
				default:
					JTextField textField = (JTextField) pc.getDisplayComponent();
					state.addEnvironmentVar(key, textField.getText());
					break;
			}
		}
	}

	public void currentProgramChanged() {
		for (String string2 : parameters.keySet()) {//OMG!!
			String key = string2.toString();
			ParamComponent pc = parameters.get(key);
			switch (pc.getType()) {
				case ADDRESS:
					AddressInput addressInput = (AddressInput) pc.getDisplayComponent();
					addressInput.setAddressFactory(state.getCurrentProgram().getAddressFactory());
					addressInput.selectDefaultAddressSpace();
					addressInput.select();
					if (panelShown()) {
						state.addEnvironmentVar(key, addressInput.getAddress());
					}
					break;
			}
		}
	}

	public boolean panelShown() {
		return shown;
	}

	public void setShown(boolean shown) {
		this.shown = shown;
	}

	public class ParamComponent {
		private int type;
		private Component displayComponent;

		public ParamComponent(Component displayComponent, int type) {
			this.displayComponent = displayComponent;
			this.type = type;
		}

		public Component getDisplayComponent() {
			return displayComponent;
		}

		public int getType() {
			return type;
		}
	}
}
