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
package ghidra.framework.plugintool;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.*;

import ghidra.framework.plugintool.testplugins.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;

public class PluginManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		runSwing(() -> tool.setConfigChanged(false));
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testConflictPluginNames() {
		// Test loading a plugin that has a name conflict with another plugin
		try {
			tool.addPlugin(NameConflictingPlugin.class.getName());
			fail("Should have gotten a plugin exception because of the conflicting plugin names");
		}
		catch (PluginException e) {
			// ensure that the exception message mentions both of the conflicting plugin class names.
			String msg = e.getMessage();
			assertTrue(msg.contains(NameConflictingPlugin.class.getName()));
			assertTrue(msg.contains(
				ghidra.framework.plugintool.testplugins.secondconflict.NameConflictingPlugin.class.getName()));
		}
		assertNotPlugin(NameConflictingPlugin.class);
		assertNotPlugin(
			ghidra.framework.plugintool.testplugins.secondconflict.NameConflictingPlugin.class);
	}

	@Test
	public void testDiamond() throws PluginException {
		// Test loading a plugin (A) that has dependencies in a diamond shape.
		//     A
		//   /   \
		//  B     C
		//   \   /
		//     D
		tool.addPlugin(DiamondPluginA.class.getName());

		assertPlugin(DiamondPluginA.class);
		assertPlugin(DiamondPluginB.class);
		assertPlugin(DiamondPluginC.class);
		assertPlugin(DiamondPluginD.class);
		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testCircularDependency() throws PluginException {
		// Test loading plugins that have circular dependencies.
		// Currently this is allowed but a warning is logged to the message console.
		//   +---------+
		//   |         |
		//   v         |
		//   A ------> B
		tool.addPlugin(CircularPluginA.class.getName());

		assertPlugin(CircularPluginA.class);
		assertPlugin(CircularPluginB.class);
		assertTrue(tool.hasConfigChanged());

		removePlugin(getPlugin(CircularPluginB.class), false);

		assertNotPlugin(CircularPluginA.class);
		assertNotPlugin(CircularPluginB.class);
	}

	@Test
	public void testLoadSameMultipleTimes() throws PluginException {
		// Loading the same plugin multiple times should not cause a problem and the second
		// attempt should just be ignored.
		tool.addPlugin(DiamondPluginD.class.getName());
		assertPlugin(DiamondPluginD.class);
		assertTrue(tool.hasConfigChanged());

		tool.addPlugin(DiamondPluginD.class.getName());
		// as long as we didn't get an exception everything is good
	}

	@Test
	public void testMissingDependency() throws PluginException {
		// Test loading a plugin that has an dependency without a default provider.
		int pluginCount = tool.getManagedPlugins().size();
		try {
			tool.addPlugin(MissingDepPluginA.class.getName());
			fail("PluginA should have failed to load");
		}
		catch (PluginException e) {
			String msg = e.getMessage();
			assertTrue(msg.contains("Unresolved dependency") &&
				msg.contains(MissingDepServiceB.class.getName()));
		}
		assertEquals(pluginCount, tool.getManagedPlugins().size());
		assertTrue(tool.hasConfigChanged());

		// If we manually add the missing dependency, it should now work
		tool.addPlugin(MissingDepPluginB.class.getName());
		tool.addPlugin(MissingDepPluginA.class.getName());

		assertPlugin(MissingDepPluginB.class);
		assertPlugin(MissingDepPluginA.class);
		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testLoadingDepSimultaneously() throws PluginException {
		// Load a plugin and a second plugin that provides a dependency at the same time.
		// Loading PluginA by itself would fail.
		tool.addPlugins(
			new String[] { MissingDepPluginA.class.getName(), MissingDepPluginB.class.getName() });

		assertPlugin(MissingDepPluginA.class);
		assertPlugin(MissingDepPluginB.class);
		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testInitFail() {
		// Test that a plugin that throws an error during init() is removed and cleaned up.
		int pluginCount = tool.getManagedPlugins().size();
		int disposeCountB = InitFailPluginB.disposeCount;

		setErrorsExpected(true);
		try {
			tool.addPlugin(InitFailPluginB.class.getName());
			fail(
				"PluginB should have failed to load because PluginB throws exception during init()");
		}
		catch (PluginException pe) {
			// good
			assertTrue(pe.getMessage().contains(InitFailPluginB.ERROR_MSG));
		}
		setErrorsExpected(false);

		assertEquals(disposeCountB + 1, InitFailPluginB.disposeCount);
		assertEquals(pluginCount, tool.getManagedPlugins().size());
		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testInitFailInDependency() {
		// Test that a plugin that has a dependency that throws an error during init()
		// is removed and cleaned up.
		int pluginCount = tool.getManagedPlugins().size();
		int disposeCountA = InitFailPluginA.disposeCount;
		int disposeCountB = InitFailPluginB.disposeCount;

		setErrorsExpected(true);
		try {
			tool.addPlugin(InitFailPluginA.class.getName());
			fail(
				"PluginA should have failed to load because PluginB throws exception during init()");
		}
		catch (PluginException pe) {
			// good
			assertTrue(pe.getMessage().contains(InitFailPluginB.ERROR_MSG));
		}
		setErrorsExpected(false);

		assertNotPlugin(InitFailPluginA.class);
		assertEquals(pluginCount, tool.getManagedPlugins().size());
		assertEquals(disposeCountB + 1, InitFailPluginB.disposeCount);
		assertEquals(disposeCountA + 1, InitFailPluginA.disposeCount);
	}

	@Test
	public void testDisposeFail() throws PluginException {
		// Test when a plugin throws an exception during its dispose()
		// Exceptions are logged to the console because the dispose was executed
		// on the swing thread.
		tool.addPlugin(DisposeFailPluginA.class.getName());
		assertTrue(tool.hasConfigChanged());
		Plugin pluginA = getPlugin(DisposeFailPluginA.class);

		runSwing(() -> tool.setConfigChanged(false));

		removePlugin(pluginA, true);

		assertNotPlugin(DisposeFailPluginA.class);
		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testLoadFailure_Isolated() {
		// test loading multiple plugins, good should load successfully, bad ones
		// shouldn't cause entire failure.

		setErrorsExpected(true);
		try {
			tool.addPlugins(new String[] { IsolatedFailPluginA.class.getName(),
				IsolatedFailPluginB.class.getName() });
			fail("Should have gotten an exception because PluginB was bad");
		}
		catch (PluginException pe) {
			// currently expected behavior, partial errors cause exception
		}
		setErrorsExpected(false);

		assertTrue(tool.hasConfigChanged());
		assertPlugin(IsolatedFailPluginA.class);
		assertNotPlugin(IsolatedFailPluginB.class);
	}

	@Test
	public void testUniquePluginNames() {
		// Ensure all current plugins have a unique name.
		// Build a string with a list of the bad plugins and report it at the end.

		Map<String, Class<? extends Plugin>> simpleNameToClassMap = new HashMap<>();
		Map<String, Set<Class<? extends Plugin>>> badPlugins = new HashMap<>();

		for (Class<? extends Plugin> pluginClass : ClassSearcher.getClasses(Plugin.class)) {
			if (TestingPlugin.class.isAssignableFrom(pluginClass)) {
				// ignore plugins marked with the TestingPlugin interface because
				// they are supposed to have name conflicts and other problems.
				continue;
			}
			String pluginName = PluginUtils.getPluginNameFromClass(pluginClass);
			Class<? extends Plugin> previousPluginClass =
				simpleNameToClassMap.putIfAbsent(pluginName, pluginClass);
			if (previousPluginClass != null) {
				Set<Class<? extends Plugin>> set =
					badPlugins.computeIfAbsent(pluginName, x -> new HashSet<>());
				set.add(pluginClass);
				set.add(previousPluginClass);
			}
		}

		// simplename: pluginclassname1,pluginclassname2*\n[repeat].
		String badPluginsStr = badPlugins.entrySet().stream().map( //
			entry -> entry.getKey() + ": " +
				entry.getValue().stream().map(pc -> pc.getName()).collect(Collectors.joining(",")) //
		).collect(Collectors.joining("\n"));

		assertTrue("Plugins with name collisions: " + badPluginsStr, badPluginsStr.isEmpty());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void removePlugin(Plugin p, boolean exceptional) {

		runSwing(() -> {
			try {

				tool.removePlugins(new Plugin[] { p });
			}
			catch (Exception e) {
				if (!exceptional) {
					throw new AssertException(e);
				}
			}
		});
	}

	private void assertPlugin(Class<? extends Plugin> pluginClass) {
		assertTrue("Plugin " + pluginClass.getName() + " not present",
			tool.getManagedPlugins().stream().anyMatch(p -> p.getClass() == pluginClass));
	}

	private void assertNotPlugin(Class<? extends Plugin> pluginClass) {

		List<Plugin> plugins = tool.getManagedPlugins();
		for (Plugin p : plugins) {
			assertNotSame("Plugin " + pluginClass.getName() + " loaded but shouldn't be",
				p.getClass(), pluginClass);
		}
	}

	private Plugin getPlugin(Class<? extends Plugin> pluginClass) {
		return tool.getManagedPlugins().stream().filter(
			p -> p.getClass() == pluginClass).findFirst().get();
	}
}
