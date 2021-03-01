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
package ghidra.dbg.model;

import java.util.List;
import java.util.Map;

import ghidra.dbg.target.TargetModule;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressRange;

public class TestTargetModule
		extends DefaultTestTargetObject<TestTargetObject, TestTargetModuleContainer>
		implements TargetModule {

	public final TestTargetSectionContainer sections;
	public final TestTargetSymbolNamespace symbols;
	public final TestTargetDataTypeNamespace types;

	public TestTargetModule(TestTargetModuleContainer parent, String name, AddressRange range) {
		super(parent, PathUtils.makeKey(name), "Module");
		sections = new TestTargetSectionContainer(this);
		symbols = new TestTargetSymbolNamespace(this);
		types = new TestTargetDataTypeNamespace(this);

		changeAttributes(List.of(), Map.of(
			RANGE_ATTRIBUTE_NAME, range,
			MODULE_NAME_ATTRIBUTE_NAME, name,
			sections.getName(), sections,
			symbols.getName(), symbols,
			types.getName(), types //
		), "Initialized");
	}

	public TestTargetSection addSection(String name, AddressRange range) {
		return sections.addSection(name, range);
	}
}
