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
package agent.gdb.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import agent.gdb.manager.GdbRegister;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "RegisterValue",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetStackFrameRegister
		extends DefaultTargetObject<TargetObject, GdbModelTargetStackFrameRegisterContainer>
		implements TargetRegister {

	protected static String indexRegister(GdbRegister register) {
		String name = register.getName();
		if ("".equals(name)) {
			return "UNNAMED," + register.getNumber();
		}
		return name;
	}

	protected static String keyRegister(GdbRegister register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	protected final GdbModelImpl impl;
	protected final GdbRegister register;

	protected final int bitLength;

	public GdbModelTargetStackFrameRegister(GdbModelTargetStackFrameRegisterContainer registers,
			GdbRegister register) {
		super(registers.impl, registers, keyRegister(register), "Register");
		this.impl = registers.impl;
		this.register = register;
		impl.addModelObject(register, this);

		this.bitLength = register.getSize() * 8;

		changeAttributes(List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, registers, //
			LENGTH_ATTRIBUTE_NAME, bitLength, //
			DISPLAY_ATTRIBUTE_NAME, getName(), //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Initialized");
	}

	@Override
	public String getDisplay() {
		return getCachedAttribute(DISPLAY_ATTRIBUTE_NAME).toString();
	}

	public void stateChanged(byte[] bytes) {
		BigInteger bigval = new BigInteger(1, bytes);
		String value = bigval.toString(16);
		Object oldval = getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
		boolean modified = (bigval.longValue() != 0 && value.equals(oldval));

		String newval = getName() + " : " + value;
		changeAttributes(List.of(), Map.of( //
			VALUE_ATTRIBUTE_NAME, value, //
			DISPLAY_ATTRIBUTE_NAME, newval, //
			MODIFIED_ATTRIBUTE_NAME, modified //
		), "Value Updated");
	}

}
