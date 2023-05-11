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
package ghidra.app.util.viewer.options;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyChangeListener;

import javax.swing.JComponent;

import generic.theme.Gui;
import ghidra.GhidraOptions;
import ghidra.framework.options.*;

/**
 * Class for editing Listing display properties.
 */
public class ListingDisplayOptionsEditor implements OptionsEditor {
	public static final String DEFAULT_FONT_ID = "font.listing.base";

	private OptionsGui optionsGui;
	private Options options;
	private PropertyChangeListener propertyChangeListener;

	/**
	 * Constructs a new ListingDisplayOptionsEditor.
	 * @param options the options object to edit
	 */
	public ListingDisplayOptionsEditor(Options options) {
		this.options = options;
		registerOptions();
	}

	@Override
	public void dispose() {
		if (optionsGui != null) {
			optionsGui.setOptionsPropertyChangeListener(null);
		}
		propertyChangeListener = null;
	}

	private void registerOptions() {
		String prefix = "Sets the ";
		options.registerThemeFontBinding(GhidraOptions.OPTION_BASE_FONT,
			DEFAULT_FONT_ID, null, prefix + GhidraOptions.OPTION_BASE_FONT);
		for (ScreenElement element : OptionsGui.elements) {
			String colorOptionName = element.getColorOptionName();
			options.registerThemeColorBinding(colorOptionName, element.getThemeColorId(), null,
				prefix + colorOptionName);
			String styleOptionName = element.getStyleOptionName();
			options.registerOption(styleOptionName, -1, null, prefix + styleOptionName);
		}
	}

	@Override
	public void apply() {
		if (optionsGui != null) {

			Font font = Gui.getFont(DEFAULT_FONT_ID);
			Font newFont = optionsGui.getBaseFont();
			if (!newFont.equals(font)) {
				options.setFont(GhidraOptions.OPTION_BASE_FONT, newFont);
			}

			for (ScreenElement element : OptionsGui.elements) {
				Color guiColor = element.getColor();
				Color optionColor =
					options.getColor(element.getColorOptionName(), element.getDefaultColor());
				if (!optionColor.equals(guiColor)) {
					options.setColor(element.getColorOptionName(), guiColor);
				}

				int optionStyle = options.getInt(element.getStyleOptionName(), -1);
				int guiStyle = element.getStyle();
				if (optionStyle != guiStyle) {
					options.setInt(element.getStyleOptionName(), guiStyle);
				}
			}

		}
	}

	@Override
	public void cancel() {
		// no changes to undo
	}

	@Override
	public void reload() {
		// nothing to do, as this component is reloaded when options are changed
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;

		if (optionsGui != null) {
			optionsGui.setOptionsPropertyChangeListener(listener);
		}
	}

	/**
	 * Returns true if this component has "good" resizing behavior.  Components
	 * that do not have this property will be placed in a scrolled pane.
	 * @return true if resizable
	 */
	public boolean isResizable() {
		return true;
	}

	@Override
	public JComponent getEditorComponent(Options editableOptions,
			EditorStateFactory editorStateFactory) {
		Font font = Gui.getFont(DEFAULT_FONT_ID);
		for (ScreenElement element : OptionsGui.elements) {
			Color c = options.getColor(element.getColorOptionName(), element.getDefaultColor());
			int style = options.getInt(element.getStyleOptionName(), -1);
			element.setColor(c);
			element.setStyle(style);
		}

		optionsGui = new OptionsGui(font, propertyChangeListener);
		return optionsGui;
	}
}
