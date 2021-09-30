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
package agent.lldb.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import SWIG.SBStream;
import SWIG.SBValue;
import agent.lldb.model.iface2.LldbModelTargetStackFrameRegister;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.ConversionUtils;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "RegisterValue",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Object.class) })
public class LldbModelTargetStackFrameRegisterImpl
		extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrameRegister {

	protected static String indexRegister(SBValue register) {
		return register.GetName();
	}

	protected static String keyRegister(SBValue register) {
		return PathUtils.makeKey(indexRegister(register));
	}

	String value = "";

	public LldbModelTargetStackFrameRegisterImpl(LldbModelTargetStackFrameRegisterBankImpl bank,
			SBValue register) {
		super(bank.getModel(), bank, keyRegister(register), register, "Register");
		value = getValue();

		changeAttributes(List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, bank.getContainer(), //
			LENGTH_ATTRIBUTE_NAME, getBitLength(), //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			VALUE_ATTRIBUTE_NAME, value == null ? "0" : value, //
			MODIFIED_ATTRIBUTE_NAME, false //
		), "Initialized");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBValue val = (SBValue) getModelObject();
		val.GetDescription(stream);
		return stream.GetData();
	}

	@Override
	public int getBitLength() {
		return (int) (getRegister().GetByteSize() * 8);
	}

	@Override
	public String getValue() {
		String val = getRegister().GetValue();
		if (val == null) {
			return null;
		}
		if (!val.startsWith("0x")) {
			return val;
		}
		return val.substring(2);
	}

	@Override
	public SBValue getRegister() {
		return (SBValue) getModelObject();
	}

	public byte[] getBytes() {
		String oldValue = value;
		value = getValue();
		if (value == null) {
			return new byte[0];
		}
		BigInteger val = new BigInteger(value, 16);
		byte[] bytes = ConversionUtils.bigIntegerToBytes((int) getRegister().GetByteSize(), val);
		changeAttributes(List.of(), Map.of( //
			VALUE_ATTRIBUTE_NAME, value //
		), "Refreshed");
		if (val.longValue() != 0) {
			String newval = getDescription(0);
			changeAttributes(List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, newval //
			), "Refreshed");
			setModified(!value.equals(oldValue));
		}
		return bytes;
	}

	public String getDisplay() {
		return getValue() == null ? getName() : getName() + " : " + getValue();
	}

}
