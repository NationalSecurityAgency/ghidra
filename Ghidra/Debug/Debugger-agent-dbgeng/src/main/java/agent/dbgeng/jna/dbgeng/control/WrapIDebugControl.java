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
package agent.dbgeng.jna.dbgeng.control;

import java.util.*;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;

public class WrapIDebugControl extends UnknownWithUtils implements IDebugControl {
	public static class ByReference extends WrapIDebugControl implements Structure.ByReference {
	}

	public WrapIDebugControl() {
	}

	public WrapIDebugControl(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetInterrupt() {
		return _invokeHR(VTIndices.GET_INTERRUPT, getPointer());
	}

	@Override
	public HRESULT SetInterrupt(ULONG Flags) {
		return _invokeHR(VTIndices.SET_INTERRUPT, getPointer(), Flags);
	}

	@Override
	public HRESULT GetInterruptTimeout(ULONGByReference Seconds) {
		return _invokeHR(VTIndices.GET_INTERRUPT_TIMEOUT, getPointer(), Seconds);
	}

	@Override
	public HRESULT SetInterruptTimeout(ULONG Seconds) {
		return _invokeHR(VTIndices.SET_INTERRUPT_TIMEOUT, getPointer(), Seconds);
	}

	@Override
	public HRESULT ReturnInput(String Buffer) {
		return _invokeHR(VTIndices.RETURN_INPUT, getPointer(), Buffer);
	}

	@Override
	public HRESULT Output(ULONG Mask, String Format, Object... objects) {
		List<Object> args = new ArrayList<>();
		args.add(getPointer());
		args.add(Format);
		args.addAll(Arrays.asList(objects));
		return _invokeHR(VTIndices.OUTPUT, args.toArray());
	}

	@Override
	public HRESULT OutputPrompt(ULONG OutputControl, String Format, Object... objects) {
		List<Object> args = new ArrayList<>();
		args.add(getPointer());
		args.add(OutputControl);
		args.add(Format);
		args.addAll(Arrays.asList(objects));
		return _invokeHR(VTIndices.OUTPUT_PROMPT, args.toArray());
	}

	@Override
	public HRESULT GetPromptText(byte[] Buffer, ULONG BufferSize, ULONGByReference TextSize) {
		return _invokeHR(VTIndices.GET_PROMPT_TEXT, getPointer(), Buffer, BufferSize, TextSize);
	}

	@Override
	public HRESULT GetExecutionStatus(ULONGByReference Status) {
		return _invokeHR(VTIndices.GET_EXECUTION_STATUS, getPointer(), Status);
	}

	@Override
	public HRESULT SetExecutionStatus(ULONG Status) {
		return _invokeHR(VTIndices.SET_EXECUTION_STATUS, getPointer(), Status);
	}

	@Override
	public HRESULT Evaluate(String Expression, ULONG DesiredType, DEBUG_VALUE.ByReference Value,
			ULONGByReference RemainderIndex) {
		return _invokeHR(VTIndices.EVALUATE, getPointer(), Expression, DesiredType, Value,
			RemainderIndex);
	}

	@Override
	public HRESULT Execute(ULONG OutputControl, String Command, ULONG Flags) {
		return _invokeHR(VTIndices.EXECUTE, getPointer(), OutputControl, Command, Flags);
	}

	@Override
	public HRESULT GetNumberBreakpoints(ULONGByReference Number) {
		return _invokeHR(VTIndices.GET_NUMBER_BREAKPOINTS, getPointer(), Number);
	}

	@Override
	public HRESULT GetBreakpointByIndex(ULONG Index, PointerByReference Bp) {
		return _invokeHR(VTIndices.GET_BREAKPOINT_BY_INDEX, getPointer(), Index, Bp);
	}

	@Override
	public HRESULT GetBreakpointById(ULONG Id, PointerByReference Bp) {
		return _invokeHR(VTIndices.GET_BREAKPOINT_BY_ID, getPointer(), Id, Bp);
	}

	@Override
	public HRESULT AddBreakpoint(ULONG Type, ULONG DesiredId, PointerByReference Bp) {
		return _invokeHR(VTIndices.ADD_BREAKPOINT, getPointer(), Type, DesiredId, Bp);
	}

	@Override
	public HRESULT RemoveBreakpoint(IDebugBreakpoint Bp) {
		return _invokeHR(VTIndices.REMOVE_BREAKPOINT, getPointer(), Bp);
	}

	@Override
	public HRESULT WaitForEvent(ULONG Flags, ULONG Timeout) {
		return _invokeHR(VTIndices.WAIT_FOR_EVENT, getPointer(), Flags, Timeout);
	}

	@Override
	public HRESULT GetLastEventInformation(ULONGByReference Type, ULONGByReference ProcessId,
			ULONGByReference ThreadId, PointerByReference ExtraInformation,
			ULONG ExtraInformationSize, ULONGByReference ExtraInformationUsed, byte[] Description,
			ULONG DescriptionSize, ULONGByReference DescriptionUsed) {
		return _invokeHR(VTIndices.GET_LAST_EVENT_INFORMATION, getPointer(), Type, ProcessId,
			ThreadId, ExtraInformation, ExtraInformationSize, ExtraInformationUsed, Description,
			DescriptionSize, DescriptionUsed);
	}

	@Override
	public HRESULT GetStackTrace(ULONGLONG FrameOffset, ULONGLONG StackOffset,
			ULONGLONG InstructionOffset, DEBUG_STACK_FRAME[] Params, ULONG FrameSize,
			ULONGByReference FramesFilled) {
		return _invokeHR(VTIndices.GET_STACK_TRACE, getPointer(), FrameOffset, StackOffset,
			InstructionOffset, Params, FrameSize, FramesFilled);
	}

	@Override
	public HRESULT GetActualProcessorType(ULONGByReference Type) {
		return _invokeHR(VTIndices.GET_ACTUAL_PROCESSOR_TYPE, getPointer(), Type);
	}

	@Override
	public HRESULT GetEffectiveProcessorType(ULONGByReference Type) {
		return _invokeHR(VTIndices.GET_EFFECTIVE_PROCESSOR_TYPE, getPointer(), Type);
	}

	@Override
	public HRESULT GetExecutingProcessorType(ULONGByReference Type) {
		return _invokeHR(VTIndices.GET_EXECUTING_PROCESSOR_TYPE, getPointer(), Type);
	}

	@Override
	public HRESULT GetDebuggeeType(ULONGByReference Class, ULONGByReference Qualifier) {
		return _invokeHR(VTIndices.GET_DEBUGGEE_TYPE, getPointer(), Class, Qualifier);
	}

}
