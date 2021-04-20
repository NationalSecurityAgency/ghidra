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
package agent.dbgeng.model.impl;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "StackFrame",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.FUNC_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.FUNC_TABLE_ENTRY_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.INST_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.FRAME_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.RETURN_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.STACK_OFFSET_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.VIRTUAL_ATTRIBUTE_NAME,
			type = Boolean.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.PARAM0_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.PARAM1_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.PARAM2_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(
			name = DbgModelTargetStackFrame.PARAM3_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetStackFrameImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetStackFrame {

	protected static String indexFrame(DbgStackFrame frame) {
		return PathUtils.makeIndex(frame.getLevel());
	}

	protected static String keyFrame(DbgStackFrame frame) {
		return PathUtils.makeKey(indexFrame(frame));
	}

	protected final DbgModelTargetThread thread;

	protected DbgStackFrame frame;
	protected Address pc;
	protected String func;
	protected String display;

	private Long funcTableEntry = -1L;
	private Long frameOffset = -1L;
	private Long returnOffset = -1L;
	private Long stackOffset = -1L;
	private Boolean virtual = false;
	private long[] params = new long[4];

	public DbgModelTargetStackFrameImpl(DbgModelTargetStack stack, DbgModelTargetThread thread,
			DbgStackFrame frame) {
		super(stack.getModel(), stack, keyFrame(frame), "StackFrame");
		this.getModel().addModelObject(frame, this);
		this.thread = thread;
		this.pc = getModel().getAddressSpace("ram").getAddress(-1);

		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame), //
			PC_ATTRIBUTE_NAME, pc //
		), "Initialized");
		setFrame(frame);

		getManager().addEventsListener(this);
	}

	protected static String computeDisplay(DbgStackFrame frame) {
		if (frame.getFunction() == null) {
			return String.format("#%d 0x%s", frame.getLevel(), frame.getAddress().toString(16));
		}
		return String.format("#%d 0x%s in %s ()", frame.getLevel(), frame.getAddress().toString(16),
			frame.getFunction());
	}

	@Override
	public void threadSelected(DbgThread eventThread, DbgStackFrame eventFrame, DbgCause cause) {
		if (eventFrame != null && eventFrame.equals(frame)) {
			((DbgModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void setFrame(DbgStackFrame frame) {
		BigInteger address = frame.getAddress();
		long lval = address == null ? -1 : address.longValue();
		this.pc = getModel().getAddressSpace("ram").getAddress(lval);
		this.func = frame.getFunction();
		if (func == null) {
			func = "UNKNOWN";
		}
		this.funcTableEntry = frame.getFuncTableEntry();
		this.frameOffset = frame.getFrameOffset();
		this.returnOffset = frame.getReturnOffset();
		this.stackOffset = frame.getStackOffset();
		this.virtual = frame.getVirtual();
		this.params = frame.getParams();
		// TODO: module? "from"
		this.frame = frame;

		changeAttributes(List.of(), List.of(), Map.of( //
			PC_ATTRIBUTE_NAME, pc, //
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(frame), //
			FUNC_ATTRIBUTE_NAME, func, //
			FUNC_TABLE_ENTRY_ATTRIBUTE_NAME, Long.toHexString(funcTableEntry), //
			INST_OFFSET_ATTRIBUTE_NAME, Long.toHexString(lval), //
			FRAME_OFFSET_ATTRIBUTE_NAME, Long.toHexString(frameOffset), //
			RETURN_OFFSET_ATTRIBUTE_NAME, Long.toHexString(returnOffset), //
			STACK_OFFSET_ATTRIBUTE_NAME, Long.toHexString(stackOffset), //
			VIRTUAL_ATTRIBUTE_NAME, virtual //
		), "Refreshed");
		changeAttributes(List.of(), List.of(), Map.of( //
			PARAM0_ATTRIBUTE_NAME, Long.toHexString(params[0]), //
			PARAM1_ATTRIBUTE_NAME, Long.toHexString(params[1]), //
			PARAM2_ATTRIBUTE_NAME, Long.toHexString(params[2]), //
			PARAM3_ATTRIBUTE_NAME, Long.toHexString(params[3]) //
		), "Refreshed");
	}

	@Override
	public TargetObject getThread() {
		return thread.getParent();
	}

	@Override
	public Address getPC() {
		return pc;
	}

	@Override
	public DbgModelTargetProcess getProcess() {
		return ((DbgModelTargetThreadImpl) thread).getProcess();
	}

	/*
	public void invalidateRegisterCaches() {
		listeners.fire.invalidateCacheRequested(this);
	}
	*/

}
