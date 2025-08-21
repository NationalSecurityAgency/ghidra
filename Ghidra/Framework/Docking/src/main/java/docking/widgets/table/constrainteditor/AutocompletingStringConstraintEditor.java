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
package docking.widgets.table.constrainteditor;

import java.awt.*;
import java.text.Collator;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DockingUtils;
import docking.widgets.DropDownTextField;
import docking.widgets.DropDownTextFieldDataModel;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.table.constraint.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.util.HTMLUtilities;

/**
 * An editor that provides suggestions of values that, according to
 * {@linkplain StringColumnConstraint}, match a user-supplied
 * pattern.
 */
public class AutocompletingStringConstraintEditor extends DataLoadingConstraintEditor<String> {

	protected DropDownTextField<String> textField;
	private AutocompleteDataModel autocompleter;

	/**
	 * Constructor.
	 *
	 * @param constraint String constraint for which this component is an editor
	 * @param columnDataSource provides access to table data and. Must be non-null.
	 */
	public AutocompletingStringConstraintEditor(StringColumnConstraint constraint,
			ColumnData<String> columnDataSource) {
		super(constraint, columnDataSource);
		autocompleter = new AutocompleteDataModel();
	}

	@Override
	protected Component buildDelegateInlineEditor() {

		JPanel panel = new JPanel(new BorderLayout());
		textField = new DropDownTextField<>(autocompleter, 100);
		textField.setIgnoreEnterKeyPress(true);
		textField.getDocument().addUndoableEditListener(e -> valueChanged());
		DockingUtils.installUndoRedo(textField);
		panel.add(textField, BorderLayout.NORTH);
		textField.addActionListener(e -> textField.closeDropDownWindow());

		return panel;
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return getConstraint().isValidPatternString(textField.getText().trim());
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// if valid, use an HTML space - otherwise the label shrinks to 0 height.
		String status =
			formatStatus(isValid ? "&nbsp;" : "Please enter a valid string to match!", true);
		statusLabel.setText(status);
	}

	@Override
	protected void resetEditor() {
		textField.setText("");
		autocompleter.clear();
	}

	@Override
	protected ColumnConstraint<String> getValueFromComponent() {
		String newPatternString = textField.getText().trim();
		return getConstraint().copy(newPatternString);
	}

	@Override
	public void handleColumnDataValue(String value) {
		autocompleter.collect(value);
	}

	@Override
	public void columnDataLoadComplete() {
		// do nothing
	}

	@Override
	public void columnDataLoadCancelled() {
		autocompleter.loadCancelled();
	}

	@Override
	public void clearColumnData() {
		autocompleter.clear();
	}

	@Override
	protected void doUpdateEditorComponent() {
		if (hasEditorComponents()) {
			textField.setText(getConstraint().getPatternString());
			textField.setCaretPosition(0);
		}
	}

	private StringColumnConstraint getConstraint() {
		return (StringColumnConstraint) currentConstraint;
	}

	/**
	 * String-based data model for the DropDownSelectionTextField. Values from the column,
	 * converted to String, are stored and queried here.
	 */
	private class AutocompleteDataModel implements DropDownTextFieldDataModel<String> {

		private final Set<String> dataSet = new HashSet<>();
		private StringColumnConstraint lastConstraint;

		@Override
		public List<String> getMatchingData(String searchText) {
			if (!isValidPatternString(searchText)) {
				return Collections.emptyList();
			}

			if (StringUtils.isBlank(searchText)) {
				// full data display not supported, as we don't know how big the data may be
				return Collections.emptyList();
			}

			searchText = searchText.trim();
			lastConstraint = (StringColumnConstraint) currentConstraint
					.parseConstraintValue(searchText, columnDataSource.getTableDataSource());

			// Use a Collator to support languages other than English.
			Collator collator = Collator.getInstance();
			collator.setStrength(Collator.SECONDARY);

			// @formatter:off
			return dataSet.stream()
					.filter(k -> lastConstraint.accepts(k, null))
					.sorted( (k1, k2) -> collator.compare(k1,  k2))
					.collect(Collectors.toList());
			// @formatter:on
		}

		private boolean isValidPatternString(String searchText) {
			StringColumnConstraint stringConstraint = (StringColumnConstraint) currentConstraint;
			return stringConstraint.isValidPatternString(searchText);
		}

		@Override
		public int getIndexOfFirstMatchingEntry(List<String> data, String text) {
			return 0;
		}

		@Override
		public ListCellRenderer<String> getListRenderer() {
			return new AutocompleteListCellRenderer(this);
		}

		@Override
		public String getDescription(String value) {
			return null;
		}

		@Override
		public String getDisplayText(String value) {
			return value;
		}

		public void collect(String value) {
			if (value == null) {
				return;
			}
			dataSet.add(value);
		}

		public void loadCancelled() {
			//	reset();
		}

		public void clear() {
			dataSet.clear();
		}

	}

	/**
	 * Cell renderer for suggestion candidates. Substrings that match the models' query are
	 * highlighted for ease-of-use.
	 */
	private class AutocompleteListCellRenderer extends GListCellRenderer<String> {

		private final AutocompleteDataModel model;

		public AutocompleteListCellRenderer(AutocompleteDataModel autocompleteDataModel) {
			this.model = autocompleteDataModel;
			this.setHTMLRenderingEnabled(true);
		}

		private String formatListValue(String value, boolean isSelected) {

			//
			// We format the matching part of the given value by using HTML to highlight the match.
			// Since we use HTML, any HTML inside of value will interfere with the HTML we add here.
			// To prevent this interference, we must escape the HTML inside of value.
			//

			// Rebuild the content by collecting all parts of the string, matching and non-matching.
			// Normally we would use the matcher to append content to the string buffer, but that
			// prevents us from being able to fix the HTML at the right time.
			Matcher matcher = model.lastConstraint.getHighlightMatcher(value);
			Color color = isSelected ? Palette.YELLOW : Palette.MAGENTA;
			StringBuilder sb = new StringBuilder("<html>");

			int start = 0;

			// find and highlight all instances of the user-defined pattern
			while (matcher.find()) {

				String group = matcher.group(1);
				int nextStart = matcher.start();
				String previousText = value.substring(start, nextStart);
				start = matcher.end();
				sb.append(HTMLUtilities.escapeHTML(previousText));

				// escape all unescaped '\' and '$' chars, as Match.appendReplacement() will treat
				// them as regex characters
				String quoted = Matcher.quoteReplacement(group);
				String escaped = HTMLUtilities.escapeHTML(quoted);
				String replacement = HTMLUtilities.colorString(color, HTMLUtilities.bold(escaped));
				sb.append(replacement);
			}

			String trailing = value.substring(start, value.length());
			sb.append(HTMLUtilities.escapeHTML(trailing));

			return sb.toString();
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends String> list, String value,
				int index, boolean isSelected, boolean cellHasFocus) {
			super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

			String valueString = formatListValue(value, isSelected);
			setText(valueString);
			return this;
		}
	}
}
