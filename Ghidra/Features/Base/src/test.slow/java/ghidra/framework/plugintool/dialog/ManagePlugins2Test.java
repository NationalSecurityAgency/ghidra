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
package ghidra.framework.plugintool.dialog;

import static org.hamcrest.collection.IsEmptyCollection.*;
import static org.hamcrest.core.IsNot.*;
import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.*;

import ghidra.app.plugin.core.help.AboutProgramPlugin;
import ghidra.app.plugin.core.totd.TipOfTheDayPlugin;
import ghidra.app.plugin.debug.JavaHelpPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import resources.ResourceManager;

/**
 * Tests for the configuring a tool.
 *
 *
 */
public class ManagePlugins2Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ManagePluginsDialog dialog;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
	}

	@After
	public void tearDown() throws Exception {
		close(dialog);
		env.dispose();

		sleep(1000);
	}

	@Test
	public void testPluginPackage_ReleasedPackage_ReleasedPlugins() throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			//
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage).build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage).build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		// test the checkbox to add/remove all plugins in the package
		assertPackageCount(1);
		assertPluginCount(testPackage, 2);

		selectAddAll(testPackage, true);
		assertLoadedPlugins(stubInstaller, pd1, pd2);

		selectAddAll(testPackage, false);
		assertNoPluginsLoaded(stubInstaller);
	}

	@Test
	public void testPluginPackage_ReleasedPackage_ReleasedAndStablePlugins() throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			//
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage)
					.status(PluginStatus.RELEASED)
					.build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		// test the checkbox to add/remove all plugins in the package
		assertPackageCount(1);
		assertPluginCount(testPackage, 2);

		selectAddAll(testPackage, true);
		assertLoadedPlugins(stubInstaller, pd1); // only 1 'released' plugin loaded

		selectAddAll(testPackage, false);
		assertNoPluginsLoaded(stubInstaller);
	}

	@Test
	public void testPluginPackage_StablePackage_ReleasedAndStablePlugins() throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			@Override
			public PluginStatus getActivationLevel() {
				return PluginStatus.STABLE;
			}
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage)
					.status(PluginStatus.RELEASED)
					.build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		// test the checkbox to add/remove all plugins in the package
		assertPackageCount(1);
		assertPluginCount(testPackage, 2);

		selectAddAll(testPackage, true);
		assertLoadedPlugins(stubInstaller, pd1, pd2); // 'released' and 'stable' plugins loaded

		selectAddAll(testPackage, false);
		assertNoPluginsLoaded(stubInstaller);
	}

	@Test
	public void testPluginPackage_StablePackage_ReleasedAndStableAndUnstablePlugins()
			throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			@Override
			public PluginStatus getActivationLevel() {
				return PluginStatus.STABLE;
			}
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage)
					.status(PluginStatus.RELEASED)
					.build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();

		StubPluginDescription pd3 =
			new StubPluginDescriptionBuilder(TipOfTheDayPlugin.class, testPackage)
					.status(PluginStatus.UNSTABLE)
					.build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);
		stubProvider.addDescription(pd3);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		// test the checkbox to add/remove all plugins in the package
		assertPackageCount(1);
		assertPluginCount(testPackage, 3);

		selectAddAll(testPackage, true);
		assertLoadedPlugins(stubInstaller, pd1, pd2); // 'released' and 'stable' plugins loaded

		selectAddAll(testPackage, false);
		assertNoPluginsLoaded(stubInstaller);
	}

	@Test
	public void testPluginPackage_ReleasedPackage_StablePlugins() throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			//
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		// test the checkbox to add/remove all plugins in the package
		assertPackageCount(1);
		assertPluginCount(testPackage, 2);

		// the checkbox is disabled since there are no plugins that meet the activation level
		assertAddAllCheckBoxDisabled(testPackage);
	}

	@Test
	public void testPluginPackageConfigure_ReleasedPackage_ReleasedAndStablePlugins()
			throws Exception {

		PluginPackage testPackage = new PluginPackage("TEST",
			ResourceManager.loadImage("images/Data_32.png"), "Test plugin pacakge") {
			//
		};

		StubPluginDescription pd1 =
			new StubPluginDescriptionBuilder(AboutProgramPlugin.class, testPackage)
					.status(PluginStatus.RELEASED)
					.build();
		StubPluginDescription pd2 =
			new StubPluginDescriptionBuilder(JavaHelpPlugin.class, testPackage)
					.status(PluginStatus.STABLE)
					.build();

		StubPluginPackagingProvider stubProvider = new StubPluginPackagingProvider();
		stubProvider.addPackage(testPackage);
		stubProvider.addDescription(pd1);
		stubProvider.addDescription(pd2);

		StubPluginInstaller stubInstaller = new StubPluginInstaller();
		PluginConfigurationModel model = new PluginConfigurationModel(stubInstaller, stubProvider);

		dialog = new ManagePluginsDialog(tool, model, false, false);
		runSwing(() -> tool.showDialog(dialog), false);

		waitForDialogComponent(ManagePluginsDialog.class);

		PluginInstallerDialog installerDialog = pressConfigure(testPackage);
		assertPluginCount(installerDialog, 2);
		close(installerDialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void selectAddAll(PluginPackage pluginPackage, boolean select) {
		PluginManagerComponent component = dialog.getPluginComponent();
		component.selectPluginPackage(pluginPackage, select);
	}

	private void assertPackageCount(int expected) {
		int actual = dialog.getPackageCount();
		assertEquals(expected, actual);
	}

	private void assertPluginCount(PluginPackage pluginPackage, int expected) {
		int actual = dialog.getPluginCount(pluginPackage);
		assertEquals(expected, actual);
	}

	private void assertLoadedPlugins(StubPluginInstaller stubInstaller,
			StubPluginDescription... descriptions) {

		Set<String> addedPlugins = stubInstaller.getAddedPlugins();
		assertEquals(descriptions.length, addedPlugins.size());
		for (PluginDescription pd : descriptions) {
			assertTrue(addedPlugins.contains(pd.getPluginClass().getName()));
		}
	}

	private void assertNoPluginsLoaded(StubPluginInstaller installer) {
		assertTrue(installer.getManagedPlugins().isEmpty());
	}

	private void assertAddAllCheckBoxDisabled(PluginPackage pluginPackage) {
		PluginManagerComponent component = dialog.getPluginComponent();
		assertTrue(runSwing(() -> component.isAddAllCheckBoxEnabled(pluginPackage)));
	}

	private PluginInstallerDialog pressConfigure(PluginPackage pluginPackage) {
		PluginManagerComponent component = dialog.getPluginComponent();
		runSwing(() -> component.managePlugins(pluginPackage), false);
		return waitForDialogComponent(PluginInstallerDialog.class);
	}

	private void assertPluginCount(PluginInstallerDialog installerDialog, int expected) {
		PluginConfigurationModel model = installerDialog.getModel();
		assertEquals(expected, model.getAllPluginDescriptions().size());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class StubPluginInstaller implements PluginInstaller {

		private List<Plugin> loadedPlugins = new ArrayList<>();
		private Set<String> addedPlugins = new HashSet<>();
		private Set<String> removedPlugins = new HashSet<>();

		@Override
		public void addPlugins(List<String> pluginClassNames) throws PluginException {
			for (String name : pluginClassNames) {
				addedPlugins.add(name);
				runSwing(() -> loadPlugin(name));
			}
		}

		private void loadPlugin(String name) {
			try {
				Class<?> clazz = Class.forName(name);
				Plugin plugin =
					(Plugin) clazz.getDeclaredConstructor(PluginTool.class).newInstance(tool);
				loadedPlugins.add(plugin);
			}
			catch (Exception e) {
				failWithException("Unable to load plugin: " + name, e);
			}
		}

		@Override
		public void removePlugins(List<Plugin> array) {
			for (Plugin plugin : array) {
				loadedPlugins.remove(plugin);
				removedPlugins.remove(plugin.getClass().getSimpleName());
			}
		}

		@Override
		public List<Plugin> getManagedPlugins() {
			return loadedPlugins;
		}

		Set<String> getAddedPlugins() {
			return addedPlugins;
		}
	}

	private class StubPluginPackagingProvider implements PluginPackagingProvider {

		private List<PluginPackage> packages = new ArrayList<>();
		private List<PluginDescription> descriptions = new ArrayList<>();
		private List<PluginDescription> unstableDescriptions = new ArrayList<>();

		@Override
		public List<PluginPackage> getPluginPackages() {
			return packages;
		}

		void addPackage(PluginPackage p) {
			packages.add(p);
		}

		@Override
		public List<PluginDescription> getPluginDescriptions() {
			return descriptions;
		}

		void addDescription(PluginDescription pd) {
			descriptions.add(pd);
		}

		@Override
		public PluginDescription getPluginDescription(String pluginClassName) {
			List<PluginDescription> results = descriptions.stream()
					.filter(pd -> pd.getPluginClass().getName().equals(pluginClassName))
					.collect(Collectors.toList());
			assertEquals(1, results.size());
			return results.get(0);
		}

		@Override
		public List<PluginDescription> getPluginDescriptions(PluginPackage pluginPackage) {
			List<PluginDescription> results = descriptions.stream()
					.filter(pd -> pd.getPluginPackage().equals(pluginPackage))
					.collect(Collectors.toList());
			assertThat(results, not(empty()));
			return results;
		}

		@Override
		public PluginPackage getUnstablePluginPackage() {
			return UNSTABLE_PACKAGE;
		}

		@Override
		public List<PluginDescription> getUnstablePluginDescriptions() {
			return unstableDescriptions;
		}
	}

	/*

	 	testPluginPackage_Released() {

	 		Click to add all

	 		Click to remove All

	 	}


		testPluginPackage_Stable_ReleasedPlugins()

		testPluginPackage_Stable_ReleasedAndStablePlugins()
	
		testPluginPackage_Stable_ReleasedAndStableAndUnstablePlugins()
			-unstable goes to 'experimental'

		testPluginPackage

	 */

}
