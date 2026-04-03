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
package ghidra.app.util.importer.options;

import java.awt.Component;

import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ghidra.app.util.*;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.AddressFactory;

/**
 * An {@link Option} used to specify a {@link String}
 */
public class StringOption extends AbstractOption<String> {

	/**
	 * Creates a new {@link IntegerOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public StringOption(String name, String value, String arg, String group, String stateKey,
			boolean hidden, String description) {
		super(name, String.class, value, arg, group, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY,
			hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		setValue(str);
		return true;
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		String defaultValue = getValue();
		String initialState =
			state != null ? state.getString(getName(), defaultValue) : defaultValue;
		setValue(initialState);
		JTextField tf = new JTextField(5);
		tf.setName(getName());
		tf.setToolTipText(getDescription());
		final StringOption thisOption = this;
		tf.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void insertUpdate(DocumentEvent e) {
				updated();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				updated();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updated();
			}

			private void updated() {
				String text = tf.getText();
				thisOption.setValue(text);
				if (state != null) {
					state.putString(thisOption.getName(), text);
				}
			}

		});
		tf.setText(getValue());
		return tf;
	}

	@Override
	public StringOption copy() {
		return new StringOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	 * Builds a {@link StringOption}
	 */
	public static class Builder extends AbstractOptionBuilder<String, StringOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link StringOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public StringOption build() {
			return new StringOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}
	}
}
