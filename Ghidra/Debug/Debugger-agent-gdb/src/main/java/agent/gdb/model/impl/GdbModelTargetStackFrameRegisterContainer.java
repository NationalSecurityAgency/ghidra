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
import java.util.*;

import agent.gdb.manager.GdbRegister;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.util.datastruct.WeakValueHashMap;

public class GdbModelTargetStackFrameRegisterContainer
		extends DefaultTargetObject<GdbModelTargetStackFrameRegister, GdbModelTargetStackFrame>
		implements TargetRegisterContainer<GdbModelTargetStackFrameRegisterContainer> {

	protected final GdbModelImpl impl;
	protected final GdbModelTargetStackFrame frame;
	protected final GdbModelTargetThread thread;

	protected final Map<Integer, GdbModelTargetStackFrameRegister> registersByNumber =
		new WeakValueHashMap<>();

	public GdbModelTargetStackFrameRegisterContainer(GdbModelTargetStackFrame frame) {
		super(frame.impl, frame, "Registers", "StackFrameRegisterContainer");
		this.impl = frame.impl;
		this.frame = frame;
		this.thread = frame.thread;
	}

	protected synchronized GdbModelTargetStackFrameRegister getTargetRegister(
			GdbRegister register) {
		return registersByNumber.computeIfAbsent(register.getNumber(),
			n -> new GdbModelTargetStackFrameRegister(this, register));
	}

	public void setValues(Map<GdbRegister, BigInteger> values) {
		List<GdbModelTargetStackFrameRegister> registers = new ArrayList<>();
		for (GdbRegister gdbreg : values.keySet()) {
			GdbModelTargetStackFrameRegister reg = getTargetRegister(gdbreg);
			registers.add(reg);
		}
		changeElements(List.of(), registers, "Refreshed");
		for (GdbModelTargetStackFrameRegister reg : registers) {
			String value = values.get(reg.register).toString(16);
			String oldval = (String) reg.getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
			reg.changeAttributes(List.of(), Map.of( //
				VALUE_ATTRIBUTE_NAME, value //
			), "Refreshed");
			if (values.get(reg.register).longValue() != 0) {
				String newval = reg.getName() + " : " + value;
				reg.changeAttributes(List.of(), Map.of( //
					DISPLAY_ATTRIBUTE_NAME, newval //
				), "Refreshed");
				reg.setModified(!value.equals(oldval));
				listeners.fire.displayChanged(this, newval);
			}
		}
	}
}
