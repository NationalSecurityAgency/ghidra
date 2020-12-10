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
package agent.dbgeng.jna.dbgeng.breakpoint;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_BREAKPOINT_PARAMETERS;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

import com.sun.jna.platform.win32.COM.IUnknown;

public interface IDebugBreakpoint extends IUnknown {
	final IID IID_IDEBUG_BREAKPOINT = new IID("5bd9d474-5975-423a-b88b-65a8e7110e65");

	enum VTIndices implements VTableIndex {
		GET_ID, //
		GET_TYPE, //
		GET_ADDER, //
		GET_FLAGS, //
		ADD_FLAGS, //
		REMOVE_FLAGS, //
		SET_FLAGS, //
		GET_OFFSET, //
		SET_OFFSET, //
		GET_DATA_PARAMETERS, //
		SET_DATA_PARAMETERS, //
		GET_PASS_COUNT, //
		SET_PASS_COUNT, //
		GET_CURRENT_PASS_COUNT, //
		GET_MATCH_THREAD_ID, //
		SET_MATCH_THREAD_ID, //
		GET_COMMAND, //
		SET_COMMAND, //
		GET_OFFSET_EXPRESSION, //
		SET_OFFSET_EXPRESSION, //
		GET_PARAMETERS, //
		;

		public int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetId(ULONGByReference Id);

	HRESULT GetType(ULONGByReference BreakType, ULONGByReference ProcType);

	HRESULT GetAdder(Pointer Adder);

	HRESULT GetFlags(ULONGByReference Flags);

	HRESULT AddFlags(ULONG Flags);

	HRESULT RemoveFlags(ULONG Flags);

	HRESULT SetFlags(ULONG Flags);

	HRESULT GetOffset(ULONGLONGByReference Offset);

	HRESULT SetOffset(ULONGLONG Offset);

	HRESULT GetDataParameters(ULONGByReference Size, ULONGByReference AcessType);

	HRESULT SetDataParameters(ULONG Size, ULONG AccessType);

	HRESULT GetPassCount(ULONGByReference Count);

	HRESULT SetPassCount(ULONG Count);

	HRESULT GetCurrentPassCount(ULONGByReference Count);

	HRESULT GetMatchThreadId(ULONGByReference Id);

	HRESULT SetMatchThreadId(ULONG Thread);

	HRESULT GetCommand(byte[] Buffer, ULONG BufferSize, ULONGByReference CommandSize);

	HRESULT SetCommand(String Command);

	HRESULT GetOffsetExpression(byte[] Buffer, ULONG BufferSize, ULONGByReference ExpressionSize);

	HRESULT SetOffsetExpression(String Expression);

	HRESULT GetParameters(DEBUG_BREAKPOINT_PARAMETERS.ByReference Params);
}
