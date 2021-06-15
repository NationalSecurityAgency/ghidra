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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;

public interface IDebugControl extends IUnknown {
	final IID IID_IDEBUG_CONTROL = new IID("5182e668-105e-416e-ad92-24ef800424ba");

	enum VTIndices implements VTableIndex {
		GET_INTERRUPT, //
		SET_INTERRUPT, //
		GET_INTERRUPT_TIMEOUT, //
		SET_INTERRUPT_TIMEOUT, //
		GET_LOG_FILE, //
		OPEN_LOG_FILE, // 
		CLOSE_LOG_FILE, //
		GET_LOG_MASK, //
		SET_LOG_MASK, //
		INPUT, //
		RETURN_INPUT, //
		OUTPUT, //
		OUTPUT_VA_LIST, // 
		CONTROLLED_OUTPUT, //
		CONTROLLED_OUTPUT_VA_LIST, //
		OUTPUT_PROMPT, //
		OUTPUT_PROMPT_VA_LIST, //
		GET_PROMPT_TEXT, //
		OUTPUT_CURRENT_STATE, //
		OUTPUT_VERSION_INFORMATION, //
		GET_NOTIFY_EVENT_HANDLE, //
		SET_NOTIFY_EVENT_HANDLE, //
		ASSEMBLE, //
		DISASSEMBLE, //
		GET_DISASSEMBLE_EFFECTIVE_OFFSET, //
		OUTPUT_DISASSEMBLY, //
		OUTPUT_DISASSEMBLY_LINES, //
		GET_NEAR_INSTRUCTION, //
		GET_STACK_TRACE, //
		GET_RETURN_OFFSET, //
		GET_OUTPUT_STACK_TRACE, //
		GET_DEBUGGEE_TYPE, //
		GET_ACTUAL_PROCESSOR_TYPE, //
		GET_EXECUTING_PROCESSOR_TYPE, //
		GET_NUMBER_POSSIBLE_EXECUTING_PROCESSOR_TYPES, //
		GET_POSSIBLE_EXECUTING_PROCESSOR_TYPES, //
		GET_NUMBER_PROCESSORS, //
		GET_SYSTEM_VERSION, //
		GET_PAGE_SIZE, //
		IS_POINTER_64BIT, //
		READ_BUG_CHECK_DATA, //
		GET_NUMBER_SUPPORTED_PROCESSOR_TYPES, //
		GET_SUPPORTED_PROCESSOR_TYPES, //
		GET_PROCESSOR_TYPE_NAMES, //
		GET_EFFECTIVE_PROCESSOR_TYPE, //
		SET_EFFECTIVE_PROCESSOR_TYPE, //
		GET_EXECUTION_STATUS, //
		SET_EXECUTION_STATUS, //
		GET_CODE_LEVEL, //
		SET_CODE_LEVEL, //
		GET_ENGINE_OPTIONS, //
		ADD_ENGINE_OPTIONS, //
		REMOVE_ENGINE_OPTIONS, //
		SET_ENGINE_OPTIONS, //
		GET_SYSTEM_ERROR_CONTROL, //
		SET_SYSTEM_ERROR_CONTROL, //
		GET_TEXT_MACRO, //
		SET_TEXT_MACRO, //
		GET_RADIX, //
		SET_RADIX, //
		EVALUATE, //
		COERCE_VALUE, //
		COERCE_VALUES, //
		EXECUTE, //
		EXECUTE_COMMAND_FILE, //
		GET_NUMBER_BREAKPOINTS, //
		GET_BREAKPOINT_BY_INDEX, //
		GET_BREAKPOINT_BY_ID, //
		GET_BREAKPOINT_PARAMETERS, //
		ADD_BREAKPOINT, //
		REMOVE_BREAKPOINT, //
		ADD_EXTENSION, //
		REMOVE_EXTENSION, //
		GET_EXTENSION_BY_PATH, //
		CALL_EXTENSION, //
		GET_EXTENSION_FUNCTION, //
		GET_WINDBG_EXTENSION_APIS32, //
		GET_WINDBG_EXTENSION_APIS64, //
		GET_NUMBER_EVENT_FILTERS, //
		GET_EVENT_FILTER_TEXT, //
		GET_EVENT_FILTER_COMMAND, //
		SET_EVENT_FILTER_COMMAND, //
		GET_SPECIFIC_FILTER_PARAMETERS, //
		SET_SPECIFIC_FILTER_PARAMETERS, //
		GET_SPECIFIC_FILTER_ARGUMENT, //
		SET_SPECIFIC_FILTER_ARGUMENT, //
		GET_EXCEPTION_FILTER_PARAMETERS, //
		SET_EXCEPTION_FILTER_PARAMETERS, //
		GET_EXCEPTION_FILTER_SECOND_COMMAND, //
		SET_EXCEPTION_FILTER_SECOND_COMMAND, //
		WAIT_FOR_EVENT, //
		GET_LAST_EVENT_INFORMATION, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetInterrupt();

	HRESULT SetInterrupt(ULONG Flags);

	HRESULT GetInterruptTimeout(ULONGByReference Seconds);

	HRESULT SetInterruptTimeout(ULONG Seconds);

	HRESULT ReturnInput(String Buffer);

	HRESULT Output(ULONG Mask, String Format, Object... objects);

	HRESULT OutputPrompt(ULONG OutputControl, String Format, Object... objects);

	HRESULT GetPromptText(byte[] Buffer, ULONG BufferSize, ULONGByReference TextSize);

	HRESULT GetExecutionStatus(ULONGByReference Status);

	HRESULT SetExecutionStatus(ULONG Status);

	HRESULT Evaluate(String Expression, ULONG DesiredType, DEBUG_VALUE.ByReference Value,
			ULONGByReference RemainderIndex);

	HRESULT Execute(ULONG OutputControl, String Command, ULONG Flags);

	HRESULT GetNumberBreakpoints(ULONGByReference Number);

	HRESULT GetBreakpointByIndex(ULONG Index, PointerByReference Bp);

	HRESULT GetBreakpointById(ULONG Id, PointerByReference Bp);

	HRESULT AddBreakpoint(ULONG Type, ULONG DesiredId, PointerByReference Bp);

	HRESULT RemoveBreakpoint(IDebugBreakpoint Bp);

	HRESULT WaitForEvent(ULONG Flags, ULONG Timeout);

	HRESULT GetLastEventInformation(ULONGByReference pulType, ULONGByReference pulProcessId,
			ULONGByReference pulThreadId, PointerByReference pExtraInformation,
			ULONG ulExtraInformationSize, ULONGByReference pulExtraInformationUsed,
			byte[] pstrDescription, ULONG ulDescriptionSize, ULONGByReference pulDescriptionUsed);

	HRESULT GetStackTrace(ULONGLONG FrameOffset, ULONGLONG StackOffset, ULONGLONG InstructionOffset,
			DEBUG_STACK_FRAME[] pParams, ULONG FrameSize, ULONGByReference FramesFilled);

	HRESULT GetActualProcessorType(ULONGByReference Type);

	HRESULT GetEffectiveProcessorType(ULONGByReference Type);

	HRESULT GetExecutingProcessorType(ULONGByReference Type);

	HRESULT GetDebuggeeType(ULONGByReference Class, ULONGByReference Qualifier);
}
