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

import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.model.iface1.FridaModelTargetFocusScope;
import agent.frida.model.iface2.*;
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
			name = "Function",
			type = FridaModelTargetFunctionImpl.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.FUNC_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.INST_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.FRAME_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.RETURN_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.CALL_FRAME_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = FridaModelTargetStackFrame.STACK_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class FridaModelTargetStackFrameImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetStackFrame {

	protected static String indexFrame(FridaFrame frame) {
		return FridaClient.getId(frame);
	}

	protected static String keyFrame(FridaFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected final FridaModelTargetThread thread;

	protected Address pc;
	protected String func;
	protected String file;
	protected String module;
	protected Long line;
	protected String display;

	private final FridaModelTargetFunctionImpl function;

	//private Long frameOffset = -1L;
	//private Long stackOffset = -1L;
	//private Long callFrameOffset = -1L;
	//private Long returnOffset = -1L;

	public FridaModelTargetStackFrameImpl(FridaModelTargetStack stack, FridaModelTargetThread thread,
			FridaFrame frame) {
		super(stack.getModel(), stack, keyFrame(frame), frame, "StackFrame");
		this.thread = thread;
		this.pc = getModel().getAddressSpace("ram").getAddress(-1);

		this.function = new FridaModelTargetFunctionImpl(this, frame.getFunction());

		changeAttributes(List.of(), List.of(
			function //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame), //
			PC_ATTRIBUTE_NAME, pc //
		), "Initialized");
		setFrame(frame);

		getManager().addEventsListener(this);
	}

	protected static String computeDisplay(FridaFrame frame) {
		if (frame.getFunctionName() == null) {
			frame.getPC();
			return String.format("#%s 0x%s", FridaClient.getId(frame), Long.toHexString(frame.getPC()));
		}
		return String.format("#%s 0x%s in %s ()", FridaClient.getId(frame), Long.toHexString(frame.getPC()),
			frame.getFunctionName());
	}

	@Override
	public void threadSelected(FridaThread eventThread, FridaFrame eventFrame, FridaCause cause) {
		if (eventFrame != null && eventFrame.equals(getFrame())) {
			((FridaModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void setFrame(FridaFrame frame) {
		setModelObject(frame);
		Long address = frame.getPC();
		long lval = address == null ? -1 : address;
		this.pc = getModel().getAddressSpace("ram").getAddress(lval);
		this.func = frame.getFunctionName();
		if (func == null) {
			func = "UNKNOWN";
		}
		this.file = frame.getFileName();
		if (file == null) {
			file = "UNKNOWN";
		}
		this.module = frame.getModuleName();
		if (module == null) {
			module = "UNKNOWN";
		}
		this.line = frame.getLineNumber();
		//this.frameOffset = frame.GetFP().longValue();
		//this.stackOffset = frame.GetSP().longValue();
		//this.callFrameOffset = frame.GetCFA().longValue();

		changeAttributes(List.of(), List.of(), Map.of( //
			PC_ATTRIBUTE_NAME, pc, //
			//DISPLAY_ATTRIBUTE_NAME, display = getDescription(0), //computeDisplay(frame), //
			FUNC_ATTRIBUTE_NAME, func //
			//FILE_ATTRIBUTE_NAME, file, //
			//MODULE_ATTRIBUTE_NAME, module, //
			//LINE_ATTRIBUTE_NAME, line //
			//INST_OFFSET_ATTRIBUTE_NAME, Long.toHexString(lval), //
			//FRAME_OFFSET_ATTRIBUTE_NAME, Long.toHexString(frameOffset), //
			//STACK_OFFSET_ATTRIBUTE_NAME, Long.toHexString(stackOffset), //
			//CALL_FRAME_OFFSET_ATTRIBUTE_NAME, Long.toHexString(callFrameOffset) //
		), "Refreshed");
	}

	@Override
	public TargetObject getThread() {
		return thread;
	}

	public FridaFrame getFrame() {
		return (FridaFrame) getModelObject();
	}

	@Override
	public Address getPC() {
		return pc;
	}

	@Override
	public FridaModelTargetProcess getProcess() {
		return ((FridaModelTargetThreadImpl) thread).getProcess();
	}

	public void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		setFrame(getFrame());
	}

}
