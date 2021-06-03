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

import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public class TestTargetSymbol
		extends DefaultTestTargetObject<TestTargetObject, TestTargetSymbolNamespace>
		implements TargetSymbol {

	public TestTargetSymbol(TestTargetSymbolNamespace parent, String name, Address address,
			long size, TargetDataType dataType) {
		super(parent, PathUtils.makeKey(name), "Symbol");

		changeAttributes(List.of(), Map.of(
			VALUE_ATTRIBUTE_NAME, address,
			DATA_TYPE_ATTRIBUTE_NAME, dataType,
			SIZE_ATTRIBUTE_NAME, size //
		), "Initialized");
	}
}
