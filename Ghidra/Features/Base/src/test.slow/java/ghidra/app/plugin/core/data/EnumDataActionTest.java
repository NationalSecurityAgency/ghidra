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
package ghidra.app.plugin.core.data;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.data.EnumDataType;

public class EnumDataActionTest extends AbstractDataActionTest {

	private EnumDataType testEnum;
	private DataPlugin dataPlugin;
	private TestEnumDataAction enumDataAction;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		testEnum = new EnumDataType("TEST_ENUM", 2);
		testEnum.add("A", 0);
		testEnum.add("B", 1);
		testEnum.add("C", 2);
		testEnum.add("D", 3);
		testEnum.add("E", 3);

		dataPlugin = getPlugin(tool, DataPlugin.class);

		enumDataAction = new TestEnumDataAction(dataPlugin);
		tool.addAction(enumDataAction);

	}

	@Test
	public void testAllEnumDataSettings() throws Exception {
		String actionName = enumDataAction.getName();
		manipulateAllSettings(false, true, false, actionName);
		manipulateAllSettings(true, true, true, actionName);
		manipulateAllSettings(false, false, false, actionName);
		manipulateAllSettings(true, false, false, actionName);
	}

	class TestEnumDataAction extends DataAction {

		public TestEnumDataAction(DataPlugin plugin) {
			super(testEnum, plugin);
		}
	}

}
