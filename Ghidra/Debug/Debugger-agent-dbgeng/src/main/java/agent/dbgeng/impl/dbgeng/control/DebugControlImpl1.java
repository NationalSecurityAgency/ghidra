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
package agent.dbgeng.impl.dbgeng.control;

import javax.help.UnsupportedOperationException;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.DebugValue.DebugValueType;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.breakpoint.DebugBreakpointInternal;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.control.IDebugControl;
import ghidra.comm.util.BitmaskSet;

public class DebugControlImpl1 implements DebugControlInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugControl jnaControl;

	public DebugControlImpl1(IDebugControl jnaControl) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaControl);
		this.jnaControl = jnaControl;
	}

	@Override
	public boolean getInterrupt() {
		HRESULT interrupt = jnaControl.GetInterrupt();
		if (interrupt.equals(WinError.S_OK)) {
			return true;
		}
		if (interrupt.equals(WinError.S_FALSE)) {
			return false;
		}
		COMUtils.checkRC(interrupt);
		throw new AssertionError("Shouldn't get here");
	}

	@Override
	public void setInterrupt(DebugInterrupt interrupt) {
		ULONG flags = new ULONG(interrupt.ordinal());
		COMUtils.checkRC(jnaControl.SetInterrupt(flags));
	}

	@Override
	public int getInterruptTimeout() {
		ULONGByReference pulSeconds = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetInterruptTimeout(pulSeconds));
		return pulSeconds.getValue().intValue();
	}

	@Override
	public void setInterruptTimeout(int seconds) {
		ULONG ulSeconds = new ULONG(seconds);
		COMUtils.checkRC(jnaControl.SetInterruptTimeout(ulSeconds));
	}

	@Override
	public void print(BitmaskSet<DebugOutputLevel> levels, String message) {
		ULONG mask = new ULONG(levels.getBitmask());
		COMUtils.checkRC(jnaControl.Output(mask, "%s", message));
	}

	@Override
	public void println(BitmaskSet<DebugOutputLevel> levels, String message) {
		ULONG mask = new ULONG(levels.getBitmask());
		COMUtils.checkRC(jnaControl.Output(mask, "%s", message + "\r\n"));
	}

	@Override
	public void prompt(BitmaskSet<DebugOutputControl> ctl, String message) {
		ULONG ctlMask = new ULONG(ctl.getBitmask());
		COMUtils.checkRC(jnaControl.OutputPrompt(ctlMask, "%s", message));
	}

	@Override
	public String getPromptText() {
		ULONGByReference pulTextSize = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetPromptText(null, new ULONG(0), pulTextSize));
		byte[] buffer = new byte[pulTextSize.getValue().intValue()];
		COMUtils.checkRC(jnaControl.GetPromptText(buffer, pulTextSize.getValue(), null));
		return Native.toString(buffer);
	}

	protected DEBUG_VALUE doEval(DebugValueType type, String expression) {
		DEBUG_VALUE.ByReference value = new DEBUG_VALUE.ByReference();
		ULONGByReference pulRemainder = new ULONGByReference();
		COMUtils.checkRC(
			jnaControl.Evaluate(expression, new ULONG(type.ordinal()), value, pulRemainder));
		int remainder = pulRemainder.getValue().intValue();
		if (remainder != expression.length()) {
			throw new RuntimeException("Failed to parse: " + expression.substring(remainder));
		}
		return value;
	}

	@Override
	public <T extends DebugValue> T evaluate(Class<T> desiredType, String expression) {
		DebugValueType type = DebugValueType.getDebugValueTypeForClass(desiredType);
		return doEval(type, expression).convertTo(desiredType);
	}

	@Override
	public void execute(BitmaskSet<DebugOutputControl> ctl, String cmd,
			BitmaskSet<DebugExecute> flags) {
		ULONG ctlMask = new ULONG(ctl.getBitmask());
		ULONG flagMask = new ULONG(flags.getBitmask());
		HRESULT hr = jnaControl.Execute(ctlMask, cmd, flagMask);
		if (hr.equals(COMUtilsExtra.E_INTERNALEXCEPTION)) {
			return;
		}
		COMUtils.checkRC(hr);
	}

	@Override
	public void returnInput(String input) {
		COMUtils.checkRC(jnaControl.ReturnInput(input));
	}

	@Override
	public DebugStatus getExecutionStatus() {
		ULONGByReference pulStatus = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetExecutionStatus(pulStatus));
		return DebugStatus.values()[pulStatus.getValue().intValue()];
	}

	@Override
	public void setExecutionStatus(DebugStatus status) {
		ULONG ulStatus = new ULONG(status.ordinal());
		HRESULT hr = jnaControl.SetExecutionStatus(ulStatus);
		if (!hr.equals(COMUtilsExtra.E_ACCESS_DENIED)) {
			COMUtils.checkRC(hr);
		}
	}

	public DebugBreakpoint doAddBreakpoint(BreakType type, ULONG ulDesiredId) {
		ULONG ulType = new ULONG(type.ordinal());
		PointerByReference ppBp = new PointerByReference();
		COMUtils.checkRC(jnaControl.AddBreakpoint(ulType, ulDesiredId, ppBp));
		IDebugBreakpoint Bp = new WrapIDebugBreakpoint(ppBp.getValue());
		DebugBreakpoint bpt =
			DebugBreakpointInternal.tryPreferredInterfaces(this, Bp::QueryInterface);
		// AddRef or no? Probably not.
		return bpt;
	}

	@Override
	public int getNumberBreakpoints() {
		ULONGByReference ulNumber = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetNumberBreakpoints(ulNumber));
		return ulNumber.getValue().intValue();
	}

	@Override
	public DebugBreakpoint getBreakpointByIndex(int index) {
		ULONG ulIndex = new ULONG(index);
		PointerByReference ppBp = new PointerByReference();
		COMUtils.checkRC(jnaControl.GetBreakpointByIndex(ulIndex, ppBp));
		IDebugBreakpoint Bp = new WrapIDebugBreakpoint(ppBp.getValue());
		DebugBreakpoint bpt =
			DebugBreakpointInternal.tryPreferredInterfaces(this, Bp::QueryInterface);
		// NOTE: Do not AddRef. dbgeng manages lifecycle
		return bpt;
	}

	@Override
	public DebugBreakpoint getBreakpointById(int id) {
		ULONG ulId = new ULONG(id);
		PointerByReference ppBp = new PointerByReference();
		HRESULT hr = jnaControl.GetBreakpointById(ulId, ppBp);
		if (hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return null;
		}
		COMUtils.checkRC(hr);
		IDebugBreakpoint Bp = new WrapIDebugBreakpoint(ppBp.getValue());
		DebugBreakpoint bpt =
			DebugBreakpointInternal.tryPreferredInterfaces(this, Bp::QueryInterface);
		// NOTE: Do not AddRef. dbgeng manages lifecycle
		return bpt;
	}

	@Override
	public DebugBreakpoint addBreakpoint(BreakType type, int desiredId) {
		return doAddBreakpoint(type, new ULONG(desiredId));
	}

	@Override
	public DebugBreakpoint addBreakpoint(BreakType type) {
		return doAddBreakpoint(type, DbgEngUtil.DEBUG_ANY_ID);
	}

	@Override
	public DebugBreakpoint addBreakpoint2(BreakType type) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DebugBreakpoint addBreakpoint2(BreakType type, int desiredId) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeBreakpoint(IDebugBreakpoint comBpt) {
		COMUtils.checkRC(jnaControl.RemoveBreakpoint(comBpt));
	}

	@Override
	public void waitForEvent(int timeout) {
		COMUtils.checkRC(jnaControl.WaitForEvent(new ULONG(0), new ULONG(timeout)));
	}

	@Override
	public DebugEventInformation getLastEventInformation() {
		ULONGByReference pulType = new ULONGByReference();
		ULONGByReference pulProcessId = new ULONGByReference();
		ULONGByReference pulThreadId = new ULONGByReference();
		//PointerByReference pExtraInformation = new PointerByReference();
		ULONG ulExtraInformationSize = new ULONG(0);
		ULONGByReference pulExtraInformationUsed = new ULONGByReference();
		//byte[] pstrDescription = new byte[0];
		ULONG ulDescriptionSize = new ULONG(0);
		ULONGByReference pulDescriptionUsed = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetLastEventInformation(pulType, pulProcessId, pulThreadId,
			null, ulExtraInformationSize, pulExtraInformationUsed, null, ulDescriptionSize,
			pulDescriptionUsed));
		return new DebugEventInformation(pulType.getValue().intValue(),
			pulProcessId.getValue().intValue(), pulThreadId.getValue().intValue());
	}

	@Override
	public DebugStackInformation getStackTrace(long frameOffset, long stackOffset,
			long instructionOffset) {
		ULONGLONG ullFrameOffset = new ULONGLONG(frameOffset);
		ULONGLONG ullStackOffset = new ULONGLONG(stackOffset);
		ULONGLONG ullInstructionOffset = new ULONGLONG(instructionOffset);
		ULONG ulFrameSize = new ULONG(100);
		DEBUG_STACK_FRAME[] pParams = new DEBUG_STACK_FRAME[ulFrameSize.intValue()];
		ULONGByReference pulFramesFilled = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetStackTrace(ullFrameOffset, ullStackOffset,
			ullInstructionOffset, pParams, ulFrameSize, pulFramesFilled));
		return new DebugStackInformation(pulFramesFilled.getValue().intValue(), pParams);
	}

	@Override
	public int getActualProcessorType() {
		ULONGByReference ulType = new ULONGByReference();
		HRESULT hr = jnaControl.GetActualProcessorType(ulType);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return ulType.getValue().intValue();
	}

	@Override
	public int getEffectiveProcessorType() {
		ULONGByReference ulType = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetEffectiveProcessorType(ulType));
		return ulType.getValue().intValue();
	}

	@Override
	public int getExecutingProcessorType() {
		ULONGByReference ulType = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetExecutingProcessorType(ulType));
		return ulType.getValue().intValue();
	}

	@Override
	public int getDebuggeeType() {
		ULONGByReference ulClass = new ULONGByReference();
		ULONGByReference ulQualifier = new ULONGByReference();
		COMUtils.checkRC(jnaControl.GetDebuggeeType(ulClass, ulQualifier));
		return ulClass.getValue().intValue();
	}
}
