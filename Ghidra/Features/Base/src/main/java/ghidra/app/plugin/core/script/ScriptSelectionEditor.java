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
package ghidra.app.plugin.core.script;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.event.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.*;
import ghidra.app.script.ScriptInfo;
import ghidra.util.HTMLUtilities;
import ghidra.util.UserSearchUtils;

/**
 * A widget that allows the user to choose an existing script by typing its name or picking it 
 * from a list.
 */
public class ScriptSelectionEditor {

	private JPanel editorPanel;
	private DropDownSelectionTextField<ScriptInfo> selectionField;
	private TreeMap<String, ScriptInfo> scriptMap = new TreeMap<>();

	// we use a simple listener data structure, since this widget is transient and nothing more
	// advanced should be needed
	private List<ScriptEditorListener> listeners = new ArrayList<>();

	ScriptSelectionEditor(List<ScriptInfo> scriptInfos) {

		scriptInfos.forEach(i -> scriptMap.put(i.getName(), i));

		init();
	}

	private void init() {

		List<ScriptInfo> sortedInfos = new ArrayList<>(scriptMap.values());

		DataToStringConverter<ScriptInfo> stringConverter = info -> info.getName();
		ScriptInfoDescriptionConverter descriptionConverter = new ScriptInfoDescriptionConverter();
		ScriptTextFieldModel model = new ScriptTextFieldModel(sortedInfos, stringConverter,
			descriptionConverter);

		selectionField = new ScriptSelectionTextField(model);

		// propagate Enter and Cancel presses to the client
		selectionField.addCellEditorListener(new CellEditorListener() {

			@Override
			public void editingStopped(ChangeEvent e) {
				fireEditingStopped();
			}

			@Override
			public void editingCanceled(ChangeEvent e) {
				fireEditingCancelled();
			}
		});

		selectionField.setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));

		editorPanel = new JPanel();
		editorPanel.setLayout(new BoxLayout(editorPanel, BoxLayout.X_AXIS));
		editorPanel.add(selectionField);
	}

	/**
	 * Adds a listener to know when the user has chosen a script info or cancelled editing.
	 * @param l the listener
	 */
	public void addEditorListener(ScriptEditorListener l) {
		listeners.remove(l);
		listeners.add(l);
	}

	/**
	 * Removes the given listener.
	 * @param l the listener
	 */
	public void removeEditorListener(ScriptEditorListener l) {
		listeners.remove(l);
	}

	/**
	 * Adds a document listener to the text field editing component of this editor so that users
	 * can be notified when the text contents of the editor change.  You may verify whether the 
	 * text changes represent a valid DataType by calling {@link #validateUserSelection()}.
	 * @param listener the listener to add.
	 * @see #validateUserSelection()
	*/
	public void addDocumentListener(DocumentListener listener) {
		selectionField.getDocument().addDocumentListener(listener);
	}

	/**
	 * Removes a previously added document listener.
	 * @param listener the listener to remove.
	 */
	public void removeDocumentListener(DocumentListener listener) {
		selectionField.getDocument().removeDocumentListener(listener);
	}

	/**
	 * Sets whether this editor should consumer Enter key presses
	 * @see DropDownSelectionTextField#setConsumeEnterKeyPress(boolean)
	 * 
	 * @param consume true to consume
	 */
	public void setConsumeEnterKeyPress(boolean consume) {
		selectionField.setConsumeEnterKeyPress(consume);
	}

	/**
	 * Returns the component that allows the user to edit.
	 * @return the component that allows the user to edit.
	 */
	public JComponent getEditorComponent() {
		return editorPanel;
	}

	/**
	 * Focuses this editors text field.
	 */
	public void requestFocus() {
		selectionField.requestFocus();
	}

	/**
	 * Returns the text value of the editor's text field.
	 * @return the text value of the editor's text field.
	 */
	public String getEditorText() {
		return selectionField.getText();
	}

	/**
	 * Returns the currently chosen script info or null.
	 * @return the currently chosen script info or null.
	 */
	public ScriptInfo getEditorValue() {
		return selectionField.getSelectedValue();
	}

	/**
	 * Returns true if the value of this editor is valid.  Clients can use this to verify that the
	 * user text is a valid script selection.
	 * @return true if the valid of this editor is valid.
	 */
	public boolean validateUserSelection() {

		// if it is not a known type, the prompt user to create new one
		if (!containsValidScript()) {
			return parseTextEntry();
		}

		return true;
	}

	private boolean containsValidScript() {
		// look for the case where the user made a selection from the matching window, but 
		// then changed the text field text.
		ScriptInfo selectedInfo = selectionField.getSelectedValue();
		if (selectedInfo != null &&
			selectionField.getText().equals(selectedInfo.getName())) {
			return true;
		}
		return false;
	}

	private boolean parseTextEntry() {

		if (StringUtils.isBlank(selectionField.getText())) {
			return false;
		}

		String text = selectionField.getText();
		ScriptInfo info = scriptMap.get(text);
		if (info != null) {
			selectionField.setSelectedValue(info);
			return true;
		}
		return false;
	}

	private void fireEditingStopped() {
		listeners.forEach(l -> l.editingStopped());
	}

	private void fireEditingCancelled() {
		listeners.forEach(l -> l.editingCancelled());
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class ScriptTextFieldModel extends DefaultDropDownSelectionDataModel<ScriptInfo> {

		public ScriptTextFieldModel(List<ScriptInfo> data,
				DataToStringConverter<ScriptInfo> searchConverter,
				DataToStringConverter<ScriptInfo> descriptionConverter) {
			super(data, searchConverter, descriptionConverter);
		}

		@Override
		public List<ScriptInfo> getMatchingData(String searchText) {

			// This pattern will: 1) allow users to match the typed text anywhere in the
			// script names and 2) allow the use of globbing characters
			Pattern pattern = UserSearchUtils.createContainsPattern(searchText, true,
				Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

			List<ScriptInfo> results = new ArrayList<>();
			for (ScriptInfo info : data) {
				String name = info.getName();
				Matcher m = pattern.matcher(name);
				if (m.matches()) {
					results.add(info);
				}
			}

			return results;
		}
	}

	private class ScriptSelectionTextField extends DropDownSelectionTextField<ScriptInfo> {

		public ScriptSelectionTextField(DropDownTextFieldDataModel<ScriptInfo> dataModel) {
			super(dataModel);
		}

		@Override
		protected boolean shouldReplaceTextFieldTextWithSelectedItem(String textFieldText,
				ScriptInfo selectedItem) {

			// This is called when the user presses Enter with a list item selected.  By 
			// default, the text field will not replace the text field text if the given item
			// does not match the text.  This is to allow users to enter custom text.  We do
			// not want custom text, as the user must pick an existing script.  Thus, we always
			// allow the replace.
			return true;
		}
	}

	private class ScriptInfoDescriptionConverter implements DataToStringConverter<ScriptInfo> {

		@Override
		public String getString(ScriptInfo info) {
			StringBuilder buffy = new StringBuilder("<HTML><P>");

			KeyStroke keyBinding = info.getKeyBinding();
			if (keyBinding != null) {
				// show the keybinding at the top softly so the user can quickly see it without
				// it interfering with the overall description
				buffy.append("<P>");
				buffy.append("<FONT COLOR=\"GRAY\"><I>&nbsp;");
				buffy.append(keyBinding.toString());
				buffy.append("</I></FONT>");
				buffy.append("<P><P>");
			}

			String description = info.getDescription();
			String formatted = formatDescription(description);
			buffy.append(formatted);

			return buffy.toString();
		}

		private String formatDescription(String description) {
			//
			// We are going to wrap lines at 50 columns so that they fit the tooltip window.  We
			// will also try to keep the original structure of manually separated lines by 
			// preserving empty lines included in the original description.  Removing all newlines
			// except for the blank lines allows the line wrapping utility to create the best 
			// output.
			//

			// split into lines and remove all leading/trailing whitespace
			String[] lines = description.split("\n");
			for (int i = 0; i < lines.length; i++) {
				String line = lines[i];
				lines[i] = line.trim();
			}

			// restore the newline characters; this will allow us to detect consecutive newlines
			StringBuilder bufffy = new StringBuilder();
			for (String line : lines) {
				bufffy.append(line).append("\n");
			}

			// Remove all newlines, except for consecutive newlines, which represent blank lines.
			// Then, for any remaining newline, add back the extra blank line.  
			String trimmed = bufffy.toString();
			String stripped = trimmed.replaceAll("(?<!\n)\n", "");
			stripped = stripped.replaceAll("\n", "\n\n");
			return HTMLUtilities.lineWrapWithHTMLLineBreaks(stripped, 50);
		}

	}
}
