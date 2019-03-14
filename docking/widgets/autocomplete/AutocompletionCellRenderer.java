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
package docking.widgets.autocomplete;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

import javax.swing.DefaultListCellRenderer;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

/**
 * This is a default list cell renderer for the {@link TextFieldAutocompleter} suitable for
 * extension if a user wishes to customize it.
 * 
 * Mostly, this just composes Swing's {@link DefaultListCellRenderer}, except it allows each
 * suggested item to specify its own text, font, icon, foreground color, and background color. Of
 * course, the display text may also use HTML tags for fine formatting. 
 * @param <T> the type of items suggested by the autocompleter.
 * @see TextFieldAutocompleter
 */
public class AutocompletionCellRenderer<T> implements ListCellRenderer<T> {
	private final TextFieldAutocompleter<T> owner;
	protected ListCellRenderer<Object> defaultRenderer = new DefaultListCellRenderer();

	/**
	 * Create a renderer owned by the given autocompleter.
	 * @param owner the autocompleter that uses (or will use) this renderer.
	 */
	public AutocompletionCellRenderer(TextFieldAutocompleter<T> owner) {
		this.owner = owner;
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends T> list, T value, int index,
			boolean isSelected, boolean cellHasFocus) {
		JLabel label = (JLabel) defaultRenderer.getListCellRendererComponent(list, value, index,
			isSelected, cellHasFocus);
		label.setText(owner.getCompletionDisplay(value));
		if (label.getText().equals("")) {
			label.setText(" ");
		}
		Font font = owner.getCompletionFont(value, isSelected, cellHasFocus);
		if (font != null) {
			label.setFont(font);
		}

		Icon icon = owner.getCompletionIcon(value, isSelected, cellHasFocus);
		if (icon != null) {
			label.setIcon(icon);
		}

		Color fg = owner.getCompletionForeground(value, isSelected, cellHasFocus);
		if (fg != null) {
			label.setForeground(fg);
		}
		Color bg = owner.getCompletionBackground(value, isSelected, cellHasFocus);
		if (bg != null) {
			label.setBackground(bg);
		}
		return label;
	}
}
