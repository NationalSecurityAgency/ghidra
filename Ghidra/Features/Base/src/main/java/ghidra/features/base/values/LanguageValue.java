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
package ghidra.features.base.values;

import java.awt.BorderLayout;
import java.io.File;
import java.util.*;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import docking.widgets.values.*;
import ghidra.app.script.SelectLanguageDialog;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

/**
 * Value class for LanguageCompilerSpecPair types. The component for this class is a 
 * TextField with a browse button for bringing up a language/compiler chooser. It supports
 * the concept of no value when the text field is empty. If it is not empty, the the contents
 * must be one of the known valid language/compiler spec pairs.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class LanguageValue extends AbstractValue<LanguageCompilerSpecPair> {
	private LangaugeValuePanel languagePanel;

	/**
	 * Construct a new LanguageVlue with no value
	 * @param name the name of the value
	 */
	public LanguageValue(String name) {
		super(name, null);
	}

	/**
	 * Construct a new LanguageVlue with a given optional default value.
	 * @param name the name of the value
	 * @param defaultValue the optional default value
	 */
	public LanguageValue(String name, LanguageCompilerSpecPair defaultValue) {
		super(name, defaultValue);
	}

	@Override
	public JComponent getComponent() {
		if (languagePanel == null) {
			languagePanel = new LangaugeValuePanel(getName());
		}
		return languagePanel;
	}

	@Override
	protected void updateValueFromComponent() throws ValuesMapParseException {
		setValue(languagePanel.getLanguage());
	}

	@Override
	protected void updateComponentFromValue() {
		languagePanel.setLanguage(getValue());
	}

	@Override
	public LanguageCompilerSpecPair fromString(String valueString) {
		try {
			return parseLanguageCompileSpecPair(valueString);
		}
		catch (ValuesMapParseException e) {
			throw new IllegalArgumentException(e.getMessage());
		}
	}

	/**
	 * Parses a LanguageCompilerSpecPair from a string. 
	 *
	 * @param languageString The string to parse.
	 * @return The LanguageCompilerSpecPair parsed from a string or null if the string does
	 * not parse to a known language-compiler pair.
	 * @throws ValuesMapParseException if the value can't be parsed into a LanguageComilerSpecPair
	 */
	public LanguageCompilerSpecPair parseLanguageCompileSpecPair(String languageString)
			throws ValuesMapParseException {

		if (languageString.isBlank()) {
			return null;
		}
		// Split on last colon to get separated languageID and compilerSpecID
		int lastColon = languageString.lastIndexOf(':');
		if (lastColon < 1) {
			throw new ValuesMapParseException(getName(), "Language/Compiler Spec",
				"Could not parse \"" + languageString + "\".");
		}

		Set<LanguageCompilerSpecPair> languages = getLanguagesCompilerPairs();

		String langId = languageString.substring(0, lastColon);
		String compilerId = languageString.substring(lastColon + 1);

		LanguageCompilerSpecPair storedLCS = new LanguageCompilerSpecPair(langId, compilerId);
		if (!languages.contains(storedLCS)) {
			throw new ValuesMapParseException(getName(), "Language/Compiler Spec",
				"Unknown language/Compiler Pair for \"" + languageString + "\"");
		}
		return storedLCS;
	}

	private Set<LanguageCompilerSpecPair> getLanguagesCompilerPairs() {
		Set<LanguageCompilerSpecPair> languages = new HashSet<>();
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		List<LanguageDescription> descriptions = languageService.getLanguageDescriptions(false);
		for (LanguageDescription description : descriptions) {
			Collection<CompilerSpecDescription> csDescriptions =
				description.getCompatibleCompilerSpecDescriptions();
			for (CompilerSpecDescription csDescription : csDescriptions) {
				languages.add(new LanguageCompilerSpecPair(description.getLanguageID(),
					csDescription.getCompilerSpecID()));
			}
		}
		return languages;
	}

	class LangaugeValuePanel extends JPanel {
		private JTextField textField;
		private JButton browseButton;

		public LangaugeValuePanel(String name) {
			super(new BorderLayout());
			setName(name);
			textField = new JTextField(20);
			browseButton = new BrowseButton();
			browseButton.addActionListener(e -> showLanguageDialog());
			add(textField, BorderLayout.CENTER);
			add(browseButton, BorderLayout.EAST);
		}

		public LanguageCompilerSpecPair getLanguage() throws ValuesMapParseException {
			return parseLanguageCompileSpecPair(textField.getText());
		}

		public void setLanguage(LanguageCompilerSpecPair value) {
			String text = value == null ? "" : value.toString();
			textField.setText(text);
		}

		private void showLanguageDialog() {
			SelectLanguageDialog dialog = new SelectLanguageDialog("Select Language", "Ok");

			try {
				dialog.setSelectedLanguage(getLanguage());
			}
			catch (ValuesMapParseException e) {
				// we are just trying to initialize dialog, so don't care at this time
			}
			dialog.show();

			LanguageCompilerSpecPair selectedLanguage = dialog.getSelectedLanguage();

			if (selectedLanguage != null) {
				textField.setText(selectedLanguage.toString());
			}
			dialog.dispose();
		}

		public File getFile() {
			String text = textField.getText().trim();
			if (text.isBlank()) {
				return null;
			}
			return new File(text);
		}

		public void setText(String val) {
			textField.setText(val);
		}

	}
}
