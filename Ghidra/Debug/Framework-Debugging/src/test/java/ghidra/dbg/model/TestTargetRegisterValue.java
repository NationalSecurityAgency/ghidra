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

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.util.PathUtils;
import ghidra.pcode.utils.Utils;

public class TestTargetRegisterValue
		extends DefaultTestTargetObject<TestTargetObject, AbstractTestTargetRegisterBank<?>>
		implements TargetRegister {

	public final TestTargetRegister desc;

	public TestTargetRegisterValue(AbstractTestTargetRegisterBank<?> parent,
			TestTargetRegister desc, BigInteger value) {
		this(parent, desc,
			value == null ? null : Utils.bigIntegerToBytes(value, desc.byteLength, true));
	}

	public TestTargetRegisterValue(AbstractTestTargetRegisterBank<?> parent,
			TestTargetRegister desc, byte[] value) {
		super(parent, PathUtils.parseIndex(desc.getName()), "Register");
		this.desc = desc;

		if (value == null) {
			changeAttributes(List.of(), Map.of(
				CONTAINER_ATTRIBUTE_NAME, parent,
				BIT_LENGTH_ATTRIBUTE_NAME, desc.byteLength * 8),
				"Populated");
		}
		else {
			changeAttributes(List.of(), Map.of(
				CONTAINER_ATTRIBUTE_NAME, parent,
				BIT_LENGTH_ATTRIBUTE_NAME, desc.byteLength * 8,
				VALUE_ATTRIBUTE_NAME, value),
				"Initialized");
		}
	}

	public void setValue(BigInteger value) {
		changeAttributes(List.of(), Map.of(
			VALUE_ATTRIBUTE_NAME, Utils.bigIntegerToBytes(value, desc.byteLength, true)),
			"Set value");
	}
}
