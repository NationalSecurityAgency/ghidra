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
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

// NB. The canonical container, but of no recognized interface
@TargetObjectSchemaInfo(name = "RegisterValueContainer", attributes = {
	@TargetAttributeType(type = Void.class)
}, canonicalContainer = true)
public class GdbModelTargetStackFrameRegisterContainer
		extends DefaultTargetObject<GdbModelTargetStackFrameRegister, GdbModelTargetStackFrame> {
	public static final String NAME = "Registers";

	protected final GdbModelImpl impl;
	protected final GdbModelTargetStackFrame frame;
	protected final GdbModelTargetThread thread;

	protected final Map<Integer, GdbModelTargetStackFrameRegister> registersByNumber =
		new WeakValueHashMap<>();

	public GdbModelTargetStackFrameRegisterContainer(GdbModelTargetStackFrame frame) {
		super(frame.impl, frame, NAME, "StackFrameRegisterContainer");
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
		for (GdbModelTargetStackFrameRegister reg : registers) {
			reg.updateValue(values.get(reg.register));
		}
		changeElements(List.of(), registers, "Refreshed");
	}
}
