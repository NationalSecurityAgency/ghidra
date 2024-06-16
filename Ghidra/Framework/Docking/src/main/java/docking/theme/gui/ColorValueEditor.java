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

import java.awt.Color;
import java.beans.PropertyChangeListener;

import docking.options.editor.ColorPropertyEditor;
import generic.theme.*;

/**
 *  Editor for Theme colors
 */
public class ColorValueEditor extends ThemeValueEditor<Color> {

	/**
	 * Constructor
	 * @param listener the {@link PropertyChangeListener} to be notified when changes are made
	 */
	public ColorValueEditor(PropertyChangeListener listener) {
		super("Color", listener, new ColorPropertyEditor());
	}

	@Override
	protected Color getRawValue(String id) {
		return Gui.getColor(id);
	}

	@Override
	protected ThemeValue<Color> createNewThemeValue(String id, Color color) {
		return new ColorValue(id, color);
	}

	@Override
	protected void storeState() {
		((ColorPropertyEditor) editor).saveState();
	}
}