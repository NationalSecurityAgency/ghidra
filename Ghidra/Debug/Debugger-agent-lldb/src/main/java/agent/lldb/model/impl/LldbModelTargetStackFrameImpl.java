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

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "StackFrame",
	attributeResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Registers",
			type = LldbModelTargetStackFrameRegisterContainerImpl.class,
			required = true),
		@TargetAttributeType(
			name = "Function",
			type = LldbModelTargetFunctionImpl.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.FUNC_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.INST_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.FRAME_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.RETURN_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.CALL_FRAME_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = LldbModelTargetStackFrame.STACK_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetStackFrameImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetStackFrame {

	protected static String indexFrame(SBFrame frame) {
		return DebugClient.getId(frame);
	}

	protected static String keyFrame(SBFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected final LldbModelTargetThread thread;

	protected Address pc;
	protected String func;
	protected String display;

	private final LldbModelTargetStackFrameRegisterContainerImpl registers;
	private final LldbModelTargetFunctionImpl function;

	private Long frameOffset = -1L;
	private Long stackOffset = -1L;
	private Long callFrameOffset = -1L;
	//private Long returnOffset = -1L;

	public LldbModelTargetStackFrameImpl(LldbModelTargetStack stack, LldbModelTargetThread thread,
			SBFrame frame) {
		super(stack.getModel(), stack, keyFrame(frame), frame, "StackFrame");
		this.thread = thread;
		this.pc = getModel().getAddressSpace("ram").getAddress(-1);

		if (!valid) {
			registers = null;
			function = null;
			return;
		}
		
		this.registers = new LldbModelTargetStackFrameRegisterContainerImpl(this);
		this.function = new LldbModelTargetFunctionImpl(this, frame.GetFunction());

		changeAttributes(List.of(), List.of(
			registers, //
			function //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //computeDisplay(frame), //
			PC_ATTRIBUTE_NAME, pc //
		), "Initialized");
		setFrame(frame);

		getManager().addEventsListener(this);
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBFrame frame = (SBFrame) getModelObject();
		frame.GetDescription(stream);
		return stream.GetData();
	}

	protected static String computeDisplay(SBFrame frame) {
		if (frame.GetFunction() == null) {
			return String.format("#%d 0x%s", DebugClient.getId(frame), frame.GetPC().toString(16));
		}
		return String.format("#%d 0x%s in %s ()", DebugClient.getId(frame), frame.GetPC().toString(16),
			frame.GetDisplayFunctionName());
	}

	@Override
	public void threadSelected(SBThread eventThread, SBFrame eventFrame, LldbCause cause) {
		if (eventFrame != null && eventFrame.equals(getFrame())) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@TargetAttributeType(
		name = LldbModelTargetStackFrameRegisterContainerImpl.NAME,
		required = true,
		fixed = true)
	public LldbModelTargetStackFrameRegisterContainer getRegisters() {
		return registers;
	}

	@Override
	public void setFrame(SBFrame frame) {
		if (!frame.IsValid()) {
			System.err.println("Error in frame");
		}
		setModelObject(frame);
		BigInteger address = frame.GetPC();
		long lval = address == null ? -1 : address.longValue();
		this.pc = getModel().getAddressSpace("ram").getAddress(lval);
		this.func = frame.GetFunctionName();
		if (func == null) {
			func = "UNKNOWN";
		}
		this.frameOffset = frame.GetFP().longValue();
		this.stackOffset = frame.GetSP().longValue();
		this.callFrameOffset = frame.GetCFA().longValue();

		changeAttributes(List.of(), List.of(), Map.of( //
			PC_ATTRIBUTE_NAME, pc, //
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //computeDisplay(frame), //
			FUNC_ATTRIBUTE_NAME, func, //
			INST_OFFSET_ATTRIBUTE_NAME, Long.toHexString(lval), //
			FRAME_OFFSET_ATTRIBUTE_NAME, Long.toHexString(frameOffset), //
			STACK_OFFSET_ATTRIBUTE_NAME, Long.toHexString(stackOffset), //
			CALL_FRAME_OFFSET_ATTRIBUTE_NAME, Long.toHexString(callFrameOffset) //
		), "Refreshed");
	}

	@Override
	public TargetObject getThread() {
		return thread;
	}

	public SBFrame getFrame() {
		return (SBFrame) getModelObject();
	}

	@Override
	public Address getPC() {
		return pc;
	}

	@Override
	public LldbModelTargetProcess getProcess() {
		return ((LldbModelTargetThreadImpl) thread).getProcess();
	}

	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		setFrame(getFrame());
		registers.threadStateChangedSpecific(state, reason);
	}

}
