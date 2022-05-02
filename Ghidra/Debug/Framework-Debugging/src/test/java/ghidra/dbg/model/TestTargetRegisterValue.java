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
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

public class TestTargetRegisterValue
		extends DefaultTestTargetObject<TestTargetObject, AbstractTestTargetRegisterBank<?>>
		implements TargetRegister {

	public static TestTargetRegisterValue fromRegisterValue(
			AbstractTestTargetRegisterBank<?> parent, RegisterValue rv) {
		Register register = rv.getRegister();
		return new TestTargetRegisterValue(parent, PathUtils.makeKey(register.getName()),
			register.isProgramCounter(), rv.getUnsignedValue(), register.getBitLength() + 7 / 8);
	}

	protected final int byteLength;
	protected final boolean isPC;

	public TestTargetRegisterValue(AbstractTestTargetRegisterBank<?> parent, String name,
			boolean isPC, BigInteger value, int byteLength) {
		this(parent, name, isPC, Utils.bigIntegerToBytes(value, byteLength, true));
	}

	public TestTargetRegisterValue(AbstractTestTargetRegisterBank<?> parent, String name,
			boolean isPC, byte[] value) {
		super(parent, name, "Register");
		this.byteLength = value.length;
		this.isPC = isPC;

		changeAttributes(List.of(), Map.of(
			CONTAINER_ATTRIBUTE_NAME, parent,
			LENGTH_ATTRIBUTE_NAME, byteLength,
			VALUE_ATTRIBUTE_NAME, value //
		), "Initialized");
	}

	public void setValue(BigInteger value) {
		changeAttributes(List.of(), Map.of(
			VALUE_ATTRIBUTE_NAME, Utils.bigIntegerToBytes(value, byteLength, true) //
		), "Set value");
	}
}
