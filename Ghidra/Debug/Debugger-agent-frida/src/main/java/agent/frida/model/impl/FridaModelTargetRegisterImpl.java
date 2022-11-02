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
package agent.frida.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import agent.frida.manager.FridaValue;
import agent.frida.model.iface2.FridaModelTargetStackFrameRegister;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.ConversionUtils;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "RegisterValue",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetRegisterImpl
		extends FridaModelTargetObjectImpl
		implements FridaModelTargetStackFrameRegister {

	protected static String indexRegister(FridaValue register) {
		return register.getKey();
	}

	protected static String keyRegister(FridaValue register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	String value = "";

	public FridaModelTargetRegisterImpl(FridaModelTargetRegisterContainerImpl registers,
			FridaValue register) {
		super(registers.getModel(), registers, keyRegister(register), register, "Register");
		value = getValue();

		changeAttributes(List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, registers, //
			BIT_LENGTH_ATTRIBUTE_NAME, getBitLength(), //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			VALUE_ATTRIBUTE_NAME, value == null ? "0" : value, //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Initialized");
	}

	@Override
	public String getDescription(int level) {
		return getName() + " : " + getValue();
	}

	@Override
	public int getBitLength() {
		return getRegister().getByteSize() * 8;
	}

	@Override
	public String getValue() {
		String val = getRegister().getValue();
		if (val == null) {
			return null;
		}
		if (!val.startsWith("0x")) {
			return val;
		}
		return val.substring(2);
	}

	@Override
	public FridaValue getRegister() {
		return (FridaValue) getModelObject();
	}

	@Override
	public byte[] getBytes() {
		String oldValue = value;
		value = getValue();
		if (value == null) {
			return new byte[0];
		}
		if (value.startsWith("{")) {
			String trim = value.substring(1, value.length() - 1);
			String[] split = trim.split(" ");
			value = split[0].substring(2) + split[1].substring(2);
		}
		BigInteger val = new BigInteger(value, 16);
		byte[] bytes = ConversionUtils.bigIntegerToBytes(getRegister().getByteSize(), val);
		changeAttributes(List.of(), Map.of( //
			VALUE_ATTRIBUTE_NAME, value //
		), "Refreshed");
		if (val.longValue() != 0) {
			String newval = getDescription(0);
			if (newval != null) {
				changeAttributes(List.of(), Map.of( //
					DISPLAY_ATTRIBUTE_NAME, newval //
				), "Refreshed");
				setModified(!value.equals(oldValue));
			}
		}
		return bytes;
	}

	@Override
	public String getDisplay() {
		return getValue() == null ? getName() : getName() + " : " + getValue();
	}

}
