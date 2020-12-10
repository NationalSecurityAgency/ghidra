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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.GdbRegister;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.util.Msg;
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

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		return completeUsingThread();
	}

	protected CompletableFuture<Void> completeUsingThread() {
		return frame.listRegisters().thenAccept(regs -> {
			List<GdbModelTargetStackFrameRegister> registers;
			synchronized (this) { // calls getTargetRegister
				// No stale garbage. New architecture may re-use numbers, so clear cache out!
				registersByNumber.clear();
				registers = regs.stream().map(this::getTargetRegister).collect(Collectors.toList());
			}
			// TODO: Equality only considers paths, i.e., name. If a name is re-used, the old
			// stuff has to go. Not sure how to accomplish that, yet.
			setElements(registers, "Refreshed");
		});
	}

	protected synchronized GdbModelTargetStackFrameRegister getTargetRegister(
			GdbRegister register) {
		return registersByNumber.computeIfAbsent(register.getNumber(),
			n -> new GdbModelTargetStackFrameRegister(this, register));
	}

	public CompletableFuture<Void> refresh() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return doRefresh().exceptionally(ex -> {
			Msg.error(this, "Problem refreshing frame's register descriptions", ex);
			return null;
		});
	}

	public void setValues(Map<GdbRegister, BigInteger> values) {
		for (GdbRegister gdbreg : values.keySet()) {
			GdbModelTargetStackFrameRegister reg = registersByNumber.get(gdbreg.getNumber());
			if (reg == null) {
				return;
			}
			String value = values.get(gdbreg).toString(16);
			String oldval = (String) reg.getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
			reg.changeAttributes(List.of(), Map.of( //
				VALUE_ATTRIBUTE_NAME, value //
			), "Refreshed");
			if (values.get(gdbreg).longValue() != 0) {
				String newval = reg.getName() + " : " + value;
				reg.changeAttributes(List.of(), Map.of( //
					DISPLAY_ATTRIBUTE_NAME, newval //
				), "Refreshed");
				reg.setModified(!value.equals(oldval));
			}
		}
	}
}
