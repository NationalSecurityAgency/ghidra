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

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.MiscellaneousPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.annotation.AutoServiceProvided;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class AutoServiceTest extends AbstractGhidraHeadedIntegrationTest {

	public interface TestService {
		// No methods, just a test service
	}

	public static class TestServiceImpl implements TestService {
		// Nothing to implement
	}

	@PluginInfo( //
			category = "Testing", //
			description = "A class for testing auto services", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "Service-annotated plugin", //
			status = PluginStatus.HIDDEN, //
			servicesProvided = TestService.class //
	)
	public static class AnnotatedServicesProvidedPlugin extends Plugin {
		@AutoServiceProvided(iface = TestService.class)
		private final TestServiceImpl testService = new TestServiceImpl();
		@SuppressWarnings("unused")
		private AutoService.Wiring autoServiceWiring;

		public AnnotatedServicesProvidedPlugin(PluginTool tool) {
			super(tool);
			autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		}
	}

	@PluginInfo( //
			category = "Testing", //
			description = "A dummy plugin for order testing", //
			packageName = MiscellaneousPluginPackage.NAME,  //
			shortDescription = "Dummy plugin", //
			status = PluginStatus.HIDDEN //
	)
	public static class DummyPlugin extends Plugin {
		public DummyPlugin(PluginTool tool) {
			super(tool);
		}
	}

	public static class AnnotatedServicesConsumedByFieldComponent {
		@AutoServiceConsumed
		private TestService testService;
		@SuppressWarnings("unused")
		private AutoService.Wiring autoServiceWiring;

		public AnnotatedServicesConsumedByFieldComponent(Plugin plugin) {
			autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		}
	}

	public static class AnnotatedServicesConsumedByMethodComponent {
		@SuppressWarnings("unused")
		private AutoService.Wiring autoServiceWiring;

		protected TestService testService;

		public AnnotatedServicesConsumedByMethodComponent(Plugin plugin) {
			autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		}

		@AutoServiceConsumed
		private void setTestService(TestService testService) {
			this.testService = testService;
		}
	}

	protected TestEnv env;
	protected PluginTool tool;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testServiceProvided() throws Exception {
		AnnotatedServicesProvidedPlugin plugin =
			addPlugin(tool, AnnotatedServicesProvidedPlugin.class);

		assertEquals(plugin.testService, tool.getService(TestService.class));
	}

	@Test
	public void testServiceConsumedByField() throws Exception {
		AnnotatedServicesProvidedPlugin plugin =
			addPlugin(tool, AnnotatedServicesProvidedPlugin.class);
		AnnotatedServicesConsumedByFieldComponent comp =
			new AnnotatedServicesConsumedByFieldComponent(plugin);

		assertEquals(plugin.testService, comp.testService);
	}

	@Test
	public void testServiceConsumedByMethod() throws Exception {
		AnnotatedServicesProvidedPlugin plugin =
			addPlugin(tool, AnnotatedServicesProvidedPlugin.class);
		AnnotatedServicesConsumedByMethodComponent comp =
			new AnnotatedServicesConsumedByMethodComponent(plugin);

		assertEquals(plugin.testService, comp.testService);
	}

	@Test
	public void testServiceConsumedBeforeProvided() throws Exception {
		DummyPlugin dummy = addPlugin(tool, DummyPlugin.class);
		AnnotatedServicesConsumedByFieldComponent comp =
			new AnnotatedServicesConsumedByFieldComponent(dummy);
		AnnotatedServicesProvidedPlugin plugin =
			addPlugin(tool, AnnotatedServicesProvidedPlugin.class);

		assertEquals(plugin.testService, comp.testService);
	}

	@Test
	public void testServiceRemoved() throws Exception {
		AnnotatedServicesProvidedPlugin plugin =
			addPlugin(tool, AnnotatedServicesProvidedPlugin.class);
		AnnotatedServicesConsumedByFieldComponent comp =
			new AnnotatedServicesConsumedByFieldComponent(plugin);

		assertEquals(plugin.testService, comp.testService);
		tool.removePlugins(new Plugin[] { plugin });
		assertEquals(null, comp.testService);
	}
}
