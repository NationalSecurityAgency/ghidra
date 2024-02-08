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
package ghidra.app.plugin.runtimeinfo;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ReusableDialogComponentProvider;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.Processor;
import ghidra.program.util.DefaultLanguageService;

/**
 * A dialog that shows the supported platforms (processors, loaders, file systems, etc)
 */
class InstalledProcessorsProvider extends ReusableDialogComponentProvider {

	private RuntimeInfoPlugin plugin;
	private JTabbedPane tabbedPane;

	/**
	 * Creates a new {@link InstalledProcessorsProvider}
	 * 
	 * @param plugin The associated {@link RuntimeInfoPlugin}
	 */
	InstalledProcessorsProvider(RuntimeInfoPlugin plugin) {
		super("Installed Processors", false, false, true, false);
		this.plugin = plugin;

		setHelpLocation(plugin.getInstalledProcessorsHelpLocation());
		addWorkPanel(createWorkPanel());
	}

	private JComponent createWorkPanel() {
		tabbedPane = new JTabbedPane();

		addProcessors();

		JPanel mainPanel = new JPanel(new BorderLayout()) {
			@Override
			public Dimension getPreferredSize() {
				return new Dimension(700, 400);
			}
		};
		mainPanel.add(tabbedPane, BorderLayout.CENTER);
		return mainPanel;
	}

	/**
	 * Adds a "processors" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display every {@link Processor} that Ghidra discovered and
	 * loaded.
	 */
	private void addProcessors() {
		Map<String, Integer> map = new HashMap<>();
		for (LanguageDescription desc : DefaultLanguageService.getLanguageService()
				.getLanguageDescriptions(true)) {
			String processor = desc.getProcessor().toString();
			int count = map.getOrDefault(processor, 0);
			map.put(processor, count + 1);
		}
		String name = "Processors";
		tabbedPane.add(
			new MapTablePanel<String, Integer>(name, map, "Name", "Variants", 300, false, plugin),
			name);
	}
}
