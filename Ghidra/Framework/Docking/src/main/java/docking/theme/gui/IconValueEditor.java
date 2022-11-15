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

import java.beans.PropertyChangeListener;

import javax.swing.Icon;

import docking.options.editor.IconPropertyEditor;
import generic.theme.*;

/**
 *  Editor for Theme fonts
 */
public class IconValueEditor extends ThemeValueEditor<Icon> {

	/**
	 * Constructor
	 * @param listener the {@link PropertyChangeListener} to be notified when changes are made
	 */
	public IconValueEditor(PropertyChangeListener listener) {
		super("Icon", listener, new IconPropertyEditor());
	}

	@Override
	protected Icon getRawValue(String id) {
		return Gui.getIcon(id);
	}

	@Override
	protected ThemeValue<Icon> createNewThemeValue(String id, Icon icon) {
		return new IconValue(id, icon);
	}

}
