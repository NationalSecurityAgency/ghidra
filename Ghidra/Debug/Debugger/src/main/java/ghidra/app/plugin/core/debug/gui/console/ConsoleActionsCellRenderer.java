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
package ghidra.app.plugin.core.debug.gui.console;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.ActionList;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.BoundAction;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;

public class ConsoleActionsCellRenderer extends AbstractGhidraColumnRenderer<ActionList> {

	static void configureBox(JPanel box) {
		box.setLayout(new BoxLayout(box, BoxLayout.X_AXIS));
		box.setOpaque(true);
		box.setAlignmentX(0.5f);
	}

	static void ensureCacheSize(List<JButton> buttonCache, int size,
			Consumer<JButton> extraConfig) {
		int diff = size - buttonCache.size();
		for (int i = 0; i < diff; i++) {
			JButton button = new JButton();
			button.setMinimumSize(DebuggerConsoleProvider.ACTION_BUTTON_DIM);
			button.setMaximumSize(DebuggerConsoleProvider.ACTION_BUTTON_DIM);
			extraConfig.accept(button);
			buttonCache.add(button);
		}
	}

	static void populateBox(JPanel box, List<JButton> buttonCache, ActionList value,
			Consumer<JButton> extraConfig) {
		box.removeAll();
		ensureCacheSize(buttonCache, value.size(), extraConfig);
		int i = 0;
		for (BoundAction a : value) {
			JButton button = buttonCache.get(i);
			button.setToolTipText(a.getTooltipText());
			button.setIcon(a.getIcon());
			button.setEnabled(a.isEnabled());
			box.add(button);
			i++;
		}
	}

	protected final JPanel box = new JPanel();
	protected final List<JButton> buttonCache = new ArrayList<>();

	public ConsoleActionsCellRenderer() {
		configureBox(box);
	}

	@Override
	public String getFilterString(ActionList t, Settings settings) {
		return t.stream().map(a -> a.getName()).collect(Collectors.joining(" "));
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data); // A bit of a waste, but sets the background
		box.setBackground(getBackground());

		ActionList value = (ActionList) data.getValue();
		populateBox(box, buttonCache, value, button -> {
		});
		return box;
	}
}
