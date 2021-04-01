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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugControl4 extends IDebugControl3 {
	final IID IID_IDEBUG_CONTROL4 = new IID("94e60ce9-9b41-4b19-9fc0-6d9eb35272b3");

	enum VTIndices4 implements VTableIndex {
		GET_LOG_FILE_WIDE, //
		OPEN_LOG_FILE_WIDE, //
		INPUT_WIDE, //
		RETURN_INPUT_WIDE, //
		OUTPUT_WIDE, //
		OUTPUT_VA_LIST_WIDE, //
		CONTROLLED_OUTPUT_WIDE, //
		CONTROLLED_OUTPUT_VA_LIST_WIDE, //
		OUTPUT_PROMPT_WIDE, //
		OUTPUT_PROMPT_VA_LIST_WIDE, //
		GET_PROMPT_TEXT_WIDE, //
		ASSEMBLE_WIDE, //
		DISASSEMBLE_WIDE, //
		GET_PROCESSOR_TYPE_NAMES_WIDE, //
		GET_TEXT_MACRO_WIDE, //
		SET_TEXT_MACRO_WIDE, //
		EVALUATE_WIDE, //
		EXECUTE_WIDE, //
		EXECUTE_COMMAND_FILE_WIDE, //
		GET_BREAKPOINT_BY_INDEX2, //
		GET_BREAKPOINT_BY_ID2, //
		ADD_BREAKPOINT2, //
		REMOVE_BREAKPOINT2, //
		ADD_EXTENSION_WIDE, //
		GET_EXTENSION_BY_PATH_WIDE, //
		CALL_EXTENSION_WIDE, //
		GET_EXTENSION_FUNCTION_WIDE, //
		GET_EVENT_FILTER_TEXT_WIDE, //
		GET_EVENT_FILTER_COMMAND_WIDE, //
		SET_EVENT_FILTER_COMMAND_WIDE, //
		GET_SPECIFIC_FILTER_ARGUMENT_WIDE, //
		SET_SPECIFIC_FILTER_ARGUMENT_WIDE, //
		GET_EXCEPTION_FILTER_SECOND_COMMAND_WIDE, //
		SET_EXCEPTION_FILTER_SECOND_COMMAND_WIDE, //
		GET_LAST_EVENT_INFORMATINO_WIDE, //
		GET_TEXT_REPLACEMENT_WIDE, //
		SET_TEXT_REPLACEMENT_WIDE, //
		SET_EXPRESSION_SYNTAX_BY_NAME_WIDE, //
		GET_EXPRESSION_SYNTAX_NAMES_WIDE, //
		GET_EVENT_INDEX_DESCRIPTION_WIDE, //
		GET_LOG_FILE2, //
		OPEN_LOG_FILE2, //
		GET_LOG_FILE2_WIDE, //
		OPEN_LOG_FILE2_WIDE, //
		GET_SYSTEM_VERSION_VALUES, //
		GET_SYSTEM_VERSION_STRING, //
		GET_SYSTEM_VERSION_STRING_WIDE, //
		GET_CONTEXT_STACK_TRACE, //
		OUTPUT_CONTEXT_STACK_TRACE, //
		GET_STORED_EVENT_INFORMATION, //
		GET_MANAGED_STATUS, //
		GET_MANAGED_STATUS_WIDE, //
		RESET_MANAGED_STATUS, //
		;

		static int start = VTableIndex.follow(VTIndices3.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT AddBreakpoint2(ULONG Type, ULONG DesiredId, PointerByReference Bp);

	HRESULT ReturnInputWide(WString Buffer);

	HRESULT OutputWide(ULONG Mask, WString Format, Object... objects);

	HRESULT OutputPromptWide(ULONG OutputControl, WString Format, Object... objects);

	HRESULT GetPromptTextWide(char[] Buffer, ULONG BufferSize, ULONGByReference TextSize);

	HRESULT EvaluateWide(WString Expression, ULONG DesiredType, DEBUG_VALUE.ByReference Value,
			ULONGByReference RemainderIndex);

	HRESULT ExecuteWide(ULONG OutputControl, WString Command, ULONG Flags);
}
