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
package docking.options.editor;

import java.awt.Color;
import java.awt.Component;
import java.beans.PropertyEditorSupport;
import java.util.*;

import javax.swing.event.ChangeListener;

import ghidra.util.Swing;

/**
 * Property Editor for Colors. Uses a {@link GhidraColorChooser} as its custom component
 */
public class ColorPropertyEditor extends PropertyEditorSupport {

	private GhidraColorChooser colorChooser;
	private ChangeListener listener = e -> colorChanged();

	private void colorChanged() {
		// run later - allows debugging without hanging the UI in some environments
		Swing.runLater(() -> setValue(colorChooser.getColor()));
	}

	@Override
	public Component getCustomEditor() {

		// always create a new one. Holding on to closed dialogs causes issues if the theme changes
		List<Color> recent = new ArrayList<>();
		List<Color> history = new ArrayList<>();
		String activeTab = null;
		if (colorChooser != null) {
			history.addAll(colorChooser.getColorHistory());
			recent.addAll(colorChooser.getRecentColors());
			activeTab = colorChooser.getActiveTab();
			colorChooser.getSelectionModel().removeChangeListener(listener);
		}
		colorChooser = new GhidraColorChooser();
		colorChooser.setColorHistory(history);
		colorChooser.setRecentColors(recent);
		colorChooser.setActiveTab(activeTab);
		colorChooser.getSelectionModel().addChangeListener(listener);
		return colorChooser;
	}

	public void saveState() {
		if (colorChooser != null) {
			colorChooser.addColorToHistory(colorChooser.getColor());
		}
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void setValue(Object value) {
		if (colorChooser != null) {
			colorChooser.setColor((Color) value);
		}
		if (!Objects.equals(value, getValue())) {
			super.setValue(value);
		}
	}
}
