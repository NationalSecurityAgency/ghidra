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
import java.util.*;

import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class TestTargetRegister
		extends DefaultTestTargetObject<TestTargetObject, TestTargetRegisterContainer>
		implements TargetRegister {

	public static TestTargetRegister fromLanguageRegister(
			TestTargetRegisterContainer parent, Register register) {
		return new TestTargetRegister(parent, PathUtils.makeKey(register.getName()),
			(register.getBitLength() + 7) / 8, register.isProgramCounter());
	}

	protected final int byteLength;
	protected final boolean isPC;

	public TestTargetRegister(TestTargetRegisterContainer parent, String name, int byteLength,
			boolean isPC) {
		super(parent, name, "Register");
		this.byteLength = byteLength;
		this.isPC = isPC;

		changeAttributes(List.of(), Map.of(
			CONTAINER_ATTRIBUTE_NAME, parent,
			LENGTH_ATTRIBUTE_NAME, byteLength //
		), "Initialized");
	}

	public byte[] normalizeValue(byte[] value) {
		if (value.length == byteLength) {
			return value;
		}
		if (value.length < byteLength) {
			byte[] result = new byte[byteLength];
			System.arraycopy(value, 0, result, byteLength - value.length, value.length);
			return result;
		}
		return Arrays.copyOfRange(value, value.length - byteLength, value.length);
	}

	public byte[] defaultValue() {
		return new byte[byteLength];
	}

	public boolean isPC() {
		return isPC;
	}

	public Address parseAddress(byte[] v) {
		return model.getAddress("ram", new BigInteger(1, v).longValue());
	}
}
