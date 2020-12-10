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
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_BREAKPOINT_PARAMETERS;

public class WrapIDebugBreakpoint extends UnknownWithUtils implements IDebugBreakpoint {
	public static class ByReference extends WrapIDebugBreakpoint implements Structure.ByReference {
	}

	public WrapIDebugBreakpoint() {
	}

	public WrapIDebugBreakpoint(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetId(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_ID, getPointer(), Id);
	}

	@Override
	public HRESULT GetType(ULONGByReference BreakType, ULONGByReference ProcType) {
		return _invokeHR(VTIndices.GET_TYPE, getPointer(), BreakType, ProcType);
	}

	@Override
	public HRESULT GetAdder(Pointer Adder) {
		return _invokeHR(VTIndices.GET_ADDER, getPointer(), Adder);
	}

	@Override
	public HRESULT GetFlags(ULONGByReference Flags) {
		return _invokeHR(VTIndices.GET_FLAGS, getPointer(), Flags);
	}

	@Override
	public HRESULT AddFlags(ULONG Flags) {
		return _invokeHR(VTIndices.ADD_FLAGS, getPointer(), Flags);
	}

	@Override
	public HRESULT RemoveFlags(ULONG Flags) {
		return _invokeHR(VTIndices.REMOVE_FLAGS, getPointer(), Flags);
	}

	@Override
	public HRESULT SetFlags(ULONG Flags) {
		return _invokeHR(VTIndices.SET_FLAGS, getPointer(), Flags);
	}

	@Override
	public HRESULT GetOffset(ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices.GET_OFFSET, getPointer(), Offset);
	}

	@Override
	public HRESULT SetOffset(ULONGLONG Offset) {
		return _invokeHR(VTIndices.SET_OFFSET, getPointer(), Offset);
	}

	@Override
	public HRESULT GetDataParameters(ULONGByReference Size, ULONGByReference AccessType) {
		return _invokeHR(VTIndices.GET_DATA_PARAMETERS, getPointer(), Size, AccessType);
	}

	@Override
	public HRESULT SetDataParameters(ULONG Size, ULONG AccessType) {
		return _invokeHR(VTIndices.SET_DATA_PARAMETERS, getPointer(), Size, AccessType);
	}

	@Override
	public HRESULT GetPassCount(ULONGByReference Count) {
		return _invokeHR(VTIndices.GET_PASS_COUNT, getPointer(), Count);
	}

	@Override
	public HRESULT SetPassCount(ULONG Count) {
		return _invokeHR(VTIndices.SET_PASS_COUNT, getPointer(), Count);
	}

	@Override
	public HRESULT GetCurrentPassCount(ULONGByReference Count) {
		return _invokeHR(VTIndices.GET_CURRENT_PASS_COUNT, getPointer(), Count);
	}

	@Override
	public HRESULT GetMatchThreadId(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_MATCH_THREAD_ID, getPointer(), Id);
	}

	@Override
	public HRESULT SetMatchThreadId(ULONG Thread) {
		return _invokeHR(VTIndices.SET_MATCH_THREAD_ID, getPointer(), Thread);
	}

	@Override
	public HRESULT GetCommand(byte[] Buffer, ULONG BufferSize, ULONGByReference CommandSize) {
		return _invokeHR(VTIndices.GET_COMMAND, getPointer(), Buffer, BufferSize, CommandSize);
	}

	@Override
	public HRESULT SetCommand(String Command) {
		return _invokeHR(VTIndices.SET_COMMAND, getPointer(), Command);
	}

	@Override
	public HRESULT GetOffsetExpression(byte[] Buffer, ULONG BufferSize,
			ULONGByReference ExpressionSize) {
		return _invokeHR(VTIndices.GET_OFFSET_EXPRESSION, getPointer(), Buffer, BufferSize,
			ExpressionSize);
	}

	@Override
	public HRESULT SetOffsetExpression(String Expression) {
		return _invokeHR(VTIndices.SET_OFFSET_EXPRESSION, getPointer(), Expression);
	}

	@Override
	public HRESULT GetParameters(DEBUG_BREAKPOINT_PARAMETERS.ByReference Params) {
		return _invokeHR(VTIndices.GET_PARAMETERS, getPointer(), Params);
	}
}
