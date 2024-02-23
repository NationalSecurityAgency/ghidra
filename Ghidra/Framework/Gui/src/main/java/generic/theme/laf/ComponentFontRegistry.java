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
package generic.theme.laf;

import java.awt.Component;
import java.awt.Font;
import java.util.Objects;

import generic.theme.Gui;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Maintains a weak set of components associated with a given font id. Whenever the font changes
 * for the font id, this class will update the component's font to the new value.
 */
public class ComponentFontRegistry {
	private WeakSet<StyledComponent> components =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private String fontId;

	/**
	 * Constructs a registry for components bound to the given font id
	 * @param fontId the id of the font to update the containing components
	 */
	public ComponentFontRegistry(String fontId) {
		this.fontId = fontId;
	}

	/**
	 * Adds a {@link Component} to the weak set of components whose font should be updated when
	 * the underlying font changes for this registry's font id.
	 * @param component the component to add
	 */
	public void addComponent(Component component) {
		addComponent(component, Font.PLAIN);
	}

	/**
	 * Allows clients to update the default font being used for a component to use the given style.
	 * @param component the component
	 * @param fontStyle the font style (e.g., {@link Font#BOLD})
	 */
	public void addComponent(Component component, int fontStyle) {
		StyledComponent sc = new StyledComponent(component, fontStyle);
		sc.setFont(Gui.getFont(fontId));
		components.add(sc);
	}

	/**
	 * Updates the font for all components bound to this registry's font id.
	 */
	public void updateComponentFonts() {
		Font font = Gui.getFont(fontId);
		for (StyledComponent c : components) {
			c.setFont(font);
		}
	}

	private record StyledComponent(Component component, int fontStyle) {

		void setFont(Font font) {
			Font existingFont = component.getFont();
			Font styledFont = font;
			int style = fontStyle();
			if (style != Font.PLAIN) {
				// Only style the font when it is not plain.  Doing this means that clients cannot
				// override a non-plain font to be plain.  If clients need that behavior, they must
				// create their own custom font id and register their component with Gui.
				styledFont = font.deriveFont(style);
			}

			if (!Objects.equals(existingFont, styledFont)) {
				component.setFont(styledFont);
			}
		}
	}
}
