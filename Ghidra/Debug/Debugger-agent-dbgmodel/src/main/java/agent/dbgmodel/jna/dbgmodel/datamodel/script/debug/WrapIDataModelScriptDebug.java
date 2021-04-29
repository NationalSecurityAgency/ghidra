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
package agent.dbgmodel.jna.dbgmodel.datamodel.script.debug;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelScriptDebug extends UnknownWithUtils implements IDataModelScriptDebug {
	public static class ByReference extends WrapIDataModelScriptDebug
			implements Structure.ByReference {
	}

	public WrapIDataModelScriptDebug() {
	}

	public WrapIDataModelScriptDebug(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT ScriptDebugState() {
		return _invokeHR(VTIndices.GET_DEBUG_STATE, getPointer());
	}

	@Override
	public HRESULT GetDebugState() {
		return _invokeHR(VTIndices.GET_DEBUG_STATE, getPointer());
	}

	@Override
	public HRESULT GetCurrentPosition(Pointer currentPosition, Pointer positionSpanEnd,
			BSTRByReference lineText) {
		return _invokeHR(VTIndices.GET_CURRENT_POSITION, getPointer(), currentPosition,
			positionSpanEnd, lineText);
	}

	@Override
	public HRESULT GetStack(PointerByReference stack) {
		return _invokeHR(VTIndices.GET_STACK, getPointer(), stack);
	}

	@Override
	public HRESULT SetBreakpoint(ULONG linePosition, ULONG columnPosition,
			PointerByReference breakpoint) {
		return _invokeHR(VTIndices.SET_BREAKPOINT, getPointer(), linePosition, columnPosition,
			breakpoint);
	}

	@Override
	public HRESULT FindBreakpointById(ULONGLONG breakpointId, PointerByReference breakpoint) {
		return _invokeHR(VTIndices.FIND_BREAKPOINT_BY_ID, getPointer(), breakpointId, breakpoint);
	}

	@Override
	public HRESULT EnumerateBreakpoints(PointerByReference breakpointEnum) {
		return _invokeHR(VTIndices.ENUMERATE_BREAKPOINTS, getPointer(), breakpointEnum);
	}

	@Override
	public HRESULT GetEventFilter(ULONG eventFilter, BOOLByReference isBreakEnabled) {
		return _invokeHR(VTIndices.GET_EVENT_FILTER, getPointer(), eventFilter, isBreakEnabled);
	}

	@Override
	public HRESULT SetEventFilter(ULONG eventFilter, BOOL isBreakEnabled) {
		return _invokeHR(VTIndices.SET_EVENT_FILTER, getPointer(), eventFilter, isBreakEnabled);
	}

	@Override
	public HRESULT StartDebugging(Pointer debugClient) {
		return _invokeHR(VTIndices.START_DEBUGGING, getPointer(), debugClient);
	}

	@Override
	public HRESULT StopDebugging(Pointer debugClient) {
		return _invokeHR(VTIndices.STOP_DEBUGGING, getPointer(), debugClient);
	}

}
