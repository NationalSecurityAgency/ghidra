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
package ghidra.framework.options;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.MiscellaneousPluginPackage;
import ghidra.framework.options.*;
import ghidra.framework.options.AutoOptions.NewValue;
import ghidra.framework.options.AutoOptions.OldValue;
import ghidra.framework.options.annotation.AutoOptionConsumed;
import ghidra.framework.options.annotation.AutoOptionDefined;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class AutoOptionsTest extends AbstractGhidraHeadedIntegrationTest {
	protected static final String OPT1_NAME = "Test Option 1";
	protected static final int OPT1_DEFAULT = 6;
	protected static final String OPT1_DESC = "A test option";
	protected static final int OPT1_NEW_VALUE = 10;

	private static final String OPT2_CATEGORY = "Testing";
	protected static final String OPT2_NAME = "Test Option 2";
	protected static final String OPT2_DEFAULT = "Default value";
	protected static final String OPT2_DESC = "Another test option";

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class",//
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsPlugin extends Plugin {
		@AutoOptionDefined(name = OPT1_NAME, description = OPT1_DESC)
		private int myIntOption = OPT1_DEFAULT;
		@AutoOptionDefined(category = OPT2_CATEGORY, name = OPT2_NAME, description = OPT2_DESC)
		private String myStringOption = OPT2_DEFAULT;
		// TODO: Proposed: move wiring into tool's addPlugin
		@SuppressWarnings("unused")
		private final AutoOptions.Wiring autoOptionsWiring;

		public AnnotatedWithOptionsPlugin(PluginTool tool) {
			super(tool);

			autoOptionsWiring = AutoOptions.wireOptions(this);
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNoParamPlugin extends AnnotatedWithOptionsPlugin {
		protected int updateNoParamCount;

		public AnnotatedWithOptionsNoParamPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNoParam() {
			this.updateNoParamCount++;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOnlyParamDefaultPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOnlyParamDefaultNew;

		public AnnotatedWithOptionsNewOnlyParamDefaultPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOnlyParamDefault(int newVal) {
			this.updateNewOnlyParamDefaultNew = newVal;
		}

	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOnlyParamAnnotatedPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOnlyParamAnnotatedNew;

		public AnnotatedWithOptionsNewOnlyParamAnnotatedPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOnlyParamAnnotated(@NewValue int newVal) {
			this.updateNewOnlyParamAnnotatedNew = newVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsOldOnlyParamAnnotatedPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateOldOnlyParamAnnotatedOld;

		public AnnotatedWithOptionsOldOnlyParamAnnotatedPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionOldOnlyParamAnnotated(@OldValue int oldVal) {
			this.updateOldOnlyParamAnnotatedOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOldParamDefaultPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOldParamDefaultNew;
		protected int updateNewOldParamDefaultOld;

		public AnnotatedWithOptionsNewOldParamDefaultPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOldParamDefault(int newVal, int oldVal) {
			this.updateNewOldParamDefaultNew = newVal;
			this.updateNewOldParamDefaultOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOldParamNewAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOldParamNewAnnotNew;
		protected int updateNewOldParamNewAnnotOld;

		public AnnotatedWithOptionsNewOldParamNewAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOldParamNewAnnot(@NewValue int newVal, int oldVal) {
			this.updateNewOldParamNewAnnotNew = newVal;
			this.updateNewOldParamNewAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOldParamOldAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOldParamOldAnnotNew;
		protected int updateNewOldParamOldAnnotOld;

		public AnnotatedWithOptionsNewOldParamOldAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOldParamOldAnnot(int newVal, @OldValue int oldVal) {
			this.updateNewOldParamOldAnnotNew = newVal;
			this.updateNewOldParamOldAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsNewOldParamNewOldAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateNewOldParamNewOldAnnotNew;
		protected int updateNewOldParamNewOldAnnotOld;

		public AnnotatedWithOptionsNewOldParamNewOldAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionNewOldParamNewOldAnnot(@NewValue int newVal,
				@OldValue int oldVal) {
			this.updateNewOldParamNewOldAnnotNew = newVal;
			this.updateNewOldParamNewOldAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsOldNewParamNewAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateOldNewParamNewAnnotNew;
		protected int updateOldNewParamNewAnnotOld;

		public AnnotatedWithOptionsOldNewParamNewAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionOldNewParamNewAnnot(int oldVal, @NewValue int newVal) {
			this.updateOldNewParamNewAnnotNew = newVal;
			this.updateOldNewParamNewAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsOldNewParamOldAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateOldNewParamOldAnnotNew;
		protected int updateOldNewParamOldAnnotOld;

		public AnnotatedWithOptionsOldNewParamOldAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionOldNewParamOldAnnot(@OldValue int oldVal, int newVal) {
			this.updateOldNewParamOldAnnotNew = newVal;
			this.updateOldNewParamOldAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "A plugin class replete with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "An annotated plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedWithOptionsOldNewParamOldNewAnnotPlugin
			extends AnnotatedWithOptionsPlugin {
		protected int updateOldNewParamOldNewAnnotNew;
		protected int updateOldNewParamOldNewAnnotOld;

		public AnnotatedWithOptionsOldNewParamOldNewAnnotPlugin(PluginTool tool) {
			super(tool);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		private void updateMyIntOptionOldNewParamOldNewAnnot(@OldValue int oldVal,
				@NewValue int newVal) {
			this.updateOldNewParamOldNewAnnotNew = newVal;
			this.updateOldNewParamOldNewAnnotOld = oldVal;
		}
	}

	@PluginInfo(//
			category = "Testing", //
			description = "Consumer-only plugin class with auto option annotations", //
			packageName = MiscellaneousPluginPackage.NAME, //
			shortDescription = "A consumer-only plugin class", //
			status = PluginStatus.HIDDEN //
	)
	public static class AnnotatedConsumerOnlyPlugin extends Plugin {
		@AutoOptionConsumed(name = OPT1_NAME)
		private int othersIntOption;
		@SuppressWarnings("unused")
		private final AutoOptions.Wiring autoOptionsWiring;

		public int updateCount;

		public int newVal;
		public int oldVal;

		public AnnotatedConsumerOnlyPlugin(PluginTool tool) {
			super(tool);

			autoOptionsWiring = AutoOptions.wireOptions(this);
		}

		@AutoOptionConsumed(name = OPT1_NAME)
		public void updateIntOption(@NewValue int newValue, @OldValue int oldValue) {
			this.newVal = newValue;
			this.oldVal = oldValue;
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
	public void testOptionsRegistered() throws PluginException {
		addPlugin(tool, AnnotatedWithOptionsPlugin.class);

		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		assertEquals(1, options.getOptionNames().size());
		Option opt1 = options.getOption(OPT1_NAME, OptionType.NO_TYPE, null);
		assertEquals(OPT1_DEFAULT, opt1.getDefaultValue());
		assertEquals(OPT1_DEFAULT, opt1.getValue(null));
		assertEquals(OPT1_DESC, opt1.getDescription());
		assertEquals(OptionType.INT_TYPE, opt1.getOptionType());
	}

	@Test
	public void testOptionsRegisteredExplicitCategory() throws PluginException {
		addPlugin(tool, AnnotatedWithOptionsPlugin.class);

		ToolOptions options = tool.getOptions(OPT2_CATEGORY);
		assertEquals(1, options.getOptionNames().size());
		Option opt2 = options.getOption(OPT2_NAME, OptionType.NO_TYPE, null);
		assertEquals(OptionType.STRING_TYPE, opt2.getOptionType());
	}

	@Test
	public void testOptionsUpdated() throws PluginException {
		AnnotatedWithOptionsPlugin plugin = addPlugin(tool, AnnotatedWithOptionsPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		assertEquals(6, plugin.myIntOption);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.myIntOption);
	}

	@Test
	public void testOptionsUpdatedByMethodNoParam() throws PluginException {
		AnnotatedWithOptionsNoParamPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNoParamPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		// An update happens right after registration
		assertEquals(1, plugin.updateNoParamCount);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(2, plugin.updateNoParamCount);
	}

	@Test
	public void testOptionsUpdatedByMethodNewOnlyParamDefault() throws PluginException {
		AnnotatedWithOptionsNewOnlyParamDefaultPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOnlyParamDefaultPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOnlyParamDefaultNew);
	}

	@Test
	public void testOptionsUpdatedByMethodNewOnlyParamAnnotated() throws PluginException {
		AnnotatedWithOptionsNewOnlyParamAnnotatedPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOnlyParamAnnotatedPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOnlyParamAnnotatedNew);
	}

	@Test
	public void testOptionsUpdatedByMethodOldOnlyParamAnnotated() throws PluginException {
		AnnotatedWithOptionsOldOnlyParamAnnotatedPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsOldOnlyParamAnnotatedPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(6, plugin.updateOldOnlyParamAnnotatedOld);
	}

	@Test
	public void testOptionsUpdatedByMethodNewOldParamDefault() throws PluginException {
		AnnotatedWithOptionsNewOldParamDefaultPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOldParamDefaultPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOldParamDefaultNew);
		assertEquals(6, plugin.updateNewOldParamDefaultOld);
	}

	@Test
	public void testOptionsUpdatedByMethodNewOldParamNewAnnotated() throws PluginException {
		AnnotatedWithOptionsNewOldParamNewAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOldParamNewAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOldParamNewAnnotNew);
		assertEquals(6, plugin.updateNewOldParamNewAnnotOld);
	}

	@Test
	public void testOptionsUpatedByMethodNewOldParamOldAnnotated() throws PluginException {
		AnnotatedWithOptionsNewOldParamOldAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOldParamOldAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOldParamOldAnnotNew);
		assertEquals(6, plugin.updateNewOldParamOldAnnotOld);
	}

	@Test
	public void testOptionsUpdatedByMethodNewOldParamNewOldAnnotated() throws PluginException {
		AnnotatedWithOptionsNewOldParamNewOldAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsNewOldParamNewOldAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateNewOldParamNewOldAnnotNew);
		assertEquals(6, plugin.updateNewOldParamNewOldAnnotOld);
	}

	@Test
	public void testOptionsUpdatedByMethodOldNewParamNewAnnotated() throws PluginException {
		AnnotatedWithOptionsOldNewParamNewAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsOldNewParamNewAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateOldNewParamNewAnnotNew);
		assertEquals(6, plugin.updateOldNewParamNewAnnotOld);
	}

	@Test
	public void testOptionsUpatedByMethodOldNewParamOldAnnotated() throws PluginException {
		AnnotatedWithOptionsOldNewParamOldAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsOldNewParamOldAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateOldNewParamOldAnnotNew);
		assertEquals(6, plugin.updateOldNewParamOldAnnotOld);
	}

	@Test
	public void testOptionsUpdatedByMethodOldNewParamOldNewAnnotated() throws PluginException {
		AnnotatedWithOptionsOldNewParamOldNewAnnotPlugin plugin =
			addPlugin(tool, AnnotatedWithOptionsOldNewParamOldNewAnnotPlugin.class);
		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		options.setInt(OPT1_NAME, OPT1_NEW_VALUE);

		assertEquals(10, plugin.updateOldNewParamOldNewAnnotNew);
		assertEquals(6, plugin.updateOldNewParamOldNewAnnotOld);
	}

	@Test
	public void testDefaultsDefinerThenConsumer() throws PluginException {
		AnnotatedWithOptionsPlugin defPlugin = addPlugin(tool, AnnotatedWithOptionsPlugin.class);
		AnnotatedConsumerOnlyPlugin consPlugin = addPlugin(tool, AnnotatedConsumerOnlyPlugin.class);

		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		Option opt1 = options.getOption(OPT1_NAME, OptionType.NO_TYPE, null);
		assertEquals(OPT1_DEFAULT, opt1.getValue(null));
		assertEquals(OPT1_DEFAULT, defPlugin.myIntOption);
		assertEquals(OPT1_DEFAULT, consPlugin.othersIntOption);
	}

	@Test
	public void testDefaultsConsumerThenDefiner() throws PluginException {
		AnnotatedConsumerOnlyPlugin consPlugin = addPlugin(tool, AnnotatedConsumerOnlyPlugin.class);
		AnnotatedWithOptionsPlugin defPlugin = addPlugin(tool, AnnotatedWithOptionsPlugin.class);

		ToolOptions options = tool.getOptions(MiscellaneousPluginPackage.NAME);
		Option opt1 = options.getOption(OPT1_NAME, OptionType.NO_TYPE, null);
		assertEquals(OPT1_DEFAULT, opt1.getValue(null));
		assertEquals(OPT1_DEFAULT, defPlugin.myIntOption);
		assertEquals(OPT1_DEFAULT, consPlugin.othersIntOption);
	}
}
