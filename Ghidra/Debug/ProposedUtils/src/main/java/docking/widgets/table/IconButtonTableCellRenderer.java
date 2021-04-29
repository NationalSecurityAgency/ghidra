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
package docking.widgets.table;

import java.awt.Component;
import java.awt.Dimension;

import javax.swing.Icon;
import javax.swing.JButton;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;

public class IconButtonTableCellRenderer
		extends AbstractGhidraColumnRenderer<String> {
	protected final JButton button = new JButton("");

	public IconButtonTableCellRenderer(Icon icon, int buttonSize) {
		button.setIcon(icon);
		button.setMinimumSize(new Dimension(buttonSize, buttonSize));
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		return button;
	}

	@Override
	public String getFilterString(String t, Settings settings) {
		return t;
	}
}
