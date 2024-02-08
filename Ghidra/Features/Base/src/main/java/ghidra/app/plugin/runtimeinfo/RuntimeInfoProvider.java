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

import java.awt.*;
import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.ReusableDialogComponentProvider;
import generic.jar.ResourceFile;
import ghidra.GhidraClassLoader;
import ghidra.framework.Application;
import ghidra.util.Disposable;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A dialog that shows useful runtime information
 */
class RuntimeInfoProvider extends ReusableDialogComponentProvider {

	private RuntimeInfoPlugin plugin;
	private JTabbedPane tabbedPane;
	private MemoryUsagePanel memoryUsagePanel;

	/**
	 * Creates a new {@link RuntimeInfoProvider}
	 * 
	 * @param plugin The associated {@link RuntimeInfoPlugin}
	 */
	RuntimeInfoProvider(RuntimeInfoPlugin plugin) {
		super("Runtime Information", false, false, true, false);
		this.plugin = plugin;


		setHelpLocation(plugin.getRuntimeInfoHelpLocation());
		addWorkPanel(createWorkPanel());
	}

	@Override
	public void dispose() {
		super.dispose();
		for (Component c : tabbedPane.getComponents()) {
			if (c instanceof Disposable d) {
				d.dispose();
			}
		}
	}

	@Override
	protected void dialogShown() {
		memoryUsagePanel.shown();
	}

	@Override
	protected void dialogClosed() {
		memoryUsagePanel.hidden();
	}


	private JComponent createWorkPanel() {
		tabbedPane = new JTabbedPane();

		addVersionInfoPanel();
		addMemory();
		addApplicationLayout();
		addProperties();
		addEnvironment();
		addModules();
		addExtensionPoints();
		addClasspath();
		addExtensionsClasspath();

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
	 * Adds a "version" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display version information that would be useful to include in 
	 * a bug report, and provide a button that copies this information to the system clipboard.
	 */
	private void addVersionInfoPanel() {
		tabbedPane.add(new VersionInfoPanel(), "Version");
	}

	/**
	 * Adds a "memory" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display live memory usage, and provide a button to initiate 
	 * garbage collection on-demand.
	 */
	private void addMemory() {
		memoryUsagePanel = new MemoryUsagePanel();
		tabbedPane.add(memoryUsagePanel, "Memory");
	}

	/**
	 * Adds an "application layout" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display information information about the application such as
	 * what directories it is using on disk, what its PID is, etc.
	 */
	private void addApplicationLayout() {
		Map<String, String> map = new HashMap<>();
		map.put("PID", ProcessHandle.current().pid() + "");
		map.put("Installation Directory", Application.getInstallationDirectory().getAbsolutePath());
		map.put("Settings Directory", Application.getUserSettingsDirectory().getPath());
		map.put("Cache Directory", Application.getUserCacheDirectory().getPath());
		map.put("Temp Directory", Application.getUserTempDirectory().getPath());
		String name = "Application Layout";
		tabbedPane.add(
			new MapTablePanel<String, String>(name, map, "Name", "Path", 200, true, plugin), name);
	}

	/**
	 * Adds a "properties" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display every defined system property in a table.
	 */
	private void addProperties() {
		Properties properties = System.getProperties();
		Map<String, String> map = new HashMap<>();
		for (Object key : properties.keySet()) {
			map.put(key.toString(), properties.getOrDefault(key, "").toString());
		}
		String name = "Properties";
		tabbedPane.add(
			new MapTablePanel<String, String>(name, map, "Name", "Value", 400, true, plugin), name);
	}

	/**
	 * Adds an "environment" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display every defined environment variable in a table.
	 */
	private void addEnvironment() {
		Map<String, String> map = System.getenv();
		String name = "Environment";
		tabbedPane.add(
			new MapTablePanel<String, String>(name, map, "Name", "Value", 400, true, plugin), name);
	}

	/**
	 * Adds a "modules" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display every module that Ghidra discovered and loaded.
	 */
	private void addModules() {
		Map<String, ResourceFile> map = Application.getApplicationLayout()
				.getModules()
				.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().getModuleRoot()));
		String name = "Modules";
		tabbedPane.add(
			new MapTablePanel<String, ResourceFile>(name, map, "Name", "Path", 400, true, plugin),
			name);
	}

	/**
	 * Adds an "extension points" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display every {@link ExtensionPoint} that Ghidra discovered and
	 * loaded.
	 */
	private void addExtensionPoints() {
		Map<String, String> map = ClassSearcher.getClasses(ExtensionPoint.class)
				.stream()
				.collect(Collectors.toMap(e -> e.getName(),
					e -> ClassSearcher.getExtensionPointName(e.getName())));
		String name = "Extension Points";
		tabbedPane.add(new MapTablePanel<String, String>(name, map, "Name", "Extension Point", 400,
			true, plugin), name);
	}

	/**
	 * Adds a "classpath" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display Ghidra's current classpath.
	 */
	private void addClasspath() {
		Map<Integer, String> map = getClasspathMap(GhidraClassLoader.CP);
		String name = "Classpath";
		tabbedPane.add(
			new MapTablePanel<Integer, String>(name, map, "Index", "Path", 40, true, plugin), name);
	}

	/**
	 * Adds an "extensions classpath" panel to the tabbed pane.
	 * <p>
	 * The goal of this panel is to display Ghidra's current extension classpath.
	 */
	private void addExtensionsClasspath() {
		Map<Integer, String> map = getClasspathMap(GhidraClassLoader.CP_EXT);
		String name = "Extensions Classpath";
		tabbedPane.add(
			new MapTablePanel<Integer, String>(name, map, "Index", "Path", 40, true, plugin), name);
	}

	/**
	 * Returns a {@link Map} of classpath entries, where the key is a 0-based integer index of each
	 * classpath entry 
	 * 
	 * @param propertyName The classpath system property name
	 * @return A {@link Map} of classpath entries, where the key is a 0-based integer index of each
	 * classpath entry 
	 */
	private Map<Integer, String> getClasspathMap(String propertyName) {
		Map<Integer, String> map = new HashMap<>();
		StringTokenizer st =
			new StringTokenizer(System.getProperty(propertyName, ""), File.pathSeparator);
		int i = 0;
		while (st.hasMoreTokens()) {
			map.put(i++, st.nextToken());
		}
		return map;
	}
}
