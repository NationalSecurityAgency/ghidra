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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbStackFrame;
import agent.gdb.manager.impl.cmd.GdbStateChangeRecord;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "StackFrame",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetStackFrame extends DefaultTargetObject<TargetObject, GdbModelTargetStack>
		implements TargetStackFrame, GdbModelSelectableObject {
	public static final String FUNC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "function";
	public static final String FROM_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "from"; // TODO

	protected static String indexFrame(GdbStackFrame frame) {
		return PathUtils.makeIndex(frame.getLevel());
	}

	protected static String keyFrame(GdbStackFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected static String computeDisplay(GdbStackFrame frame) {
		// TODO: Alternative formats when function is not known?
		return String.format("#%d 0x%s in %s ()", frame.getLevel(), frame.getAddress().toString(16),
			frame.getFunction());
	}

	protected final GdbModelImpl impl;
	protected final GdbModelTargetThread thread;
	protected final GdbModelTargetInferior inferior;

	protected GdbStackFrame frame;
	protected Address pc;
	protected String func;
	protected String display;

	private final GdbModelTargetStackFrameRegisterContainer registers;

	public GdbModelTargetStackFrame(GdbModelTargetStack stack, GdbModelTargetThread thread,
			GdbModelTargetInferior inferior, GdbStackFrame frame) {
		super(stack.impl, stack, keyFrame(frame), "StackFrame");
		this.impl = stack.impl;
		this.thread = thread;
		this.inferior = inferior;
		impl.addModelObject(frame, this);

		this.registers = new GdbModelTargetStackFrameRegisterContainer(this);

		changeAttributes(List.of(), List.of(registers), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame)),
			"Initialized");
		setFrame(frame);
	}

	@TargetAttributeType(
		name = GdbModelTargetStackFrameRegisterContainer.NAME,
		required = true,
		fixed = true)
	public GdbModelTargetStackFrameRegisterContainer getRegisters() {
		return registers;
	}

	protected void setFrame(GdbStackFrame frame) {
		frame = frame.fillWith(this.frame);
		if (this.frame == frame) {
			return;
		}
		this.frame = frame;
		this.pc = impl.space.getAddress(frame.getAddress().longValue());
		this.func = frame.getFunction();
		// TODO: module? "from"

		changeAttributes(List.of(), List.of( //
			registers //
		), Map.of( //
			PC_ATTRIBUTE_NAME, pc, //
			FUNC_ATTRIBUTE_NAME, func, //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame) //
		), "Refreshed");
	}

	protected void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}

	@Override
	@Internal
	public CompletableFuture<Void> setActive() {
		return impl.gateFuture(frame.setActive(false));
	}

	@TargetAttributeType(name = FUNC_ATTRIBUTE_NAME)
	public String getFunction() {
		return func;
	}

	@Override
	public Address getProgramCounter() {
		return pc;
	}

	public CompletableFuture<Void> stateChanged(GdbStateChangeRecord sco) {
		return registers.stateChanged(sco);
	}
}
