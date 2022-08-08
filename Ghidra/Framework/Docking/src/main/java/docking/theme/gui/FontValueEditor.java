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
package docking.theme.gui;

import java.awt.Font;
import java.beans.PropertyChangeListener;

import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.UIResource;

import docking.options.editor.FontPropertyEditor;
import docking.theme.*;
import generic.theme.*;

/**
 *  Editor for Theme fonts
 */
public class FontValueEditor extends ThemeValueEditor<Font> {

	/**
	 * Constructor
	 * @param listener the {@link PropertyChangeListener} to be notified when changes are made
	 */
	public FontValueEditor(PropertyChangeListener listener) {
		super("Font", listener, new FontPropertyEditor());
	}

	@Override
	protected Font getRawValue(String id) {
		return Gui.getFont(id);
	}

	@Override
	protected ThemeValue<Font> createNewThemeValue(String id, Font font) {
		// We need user changed values to be UIResources, otherwise the next time they change
		// the value, it won't be honored because setting UIDefaults only affects components
		// that have current UIResource fonts (So that programatic settings won't be overridden)
		if (!(font instanceof UIResource)) {
			font = new FontUIResource(font);
		}
		return new FontValue(id, font);
	}

}
