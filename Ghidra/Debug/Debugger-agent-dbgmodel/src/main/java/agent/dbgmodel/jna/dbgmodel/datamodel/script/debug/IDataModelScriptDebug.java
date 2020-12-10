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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelScriptDebug extends IUnknownEx {
	final IID IID_IDATA_MODEL_SCRIPT_DEBUG = new IID("DE8E0945-9750-4471-AB76-A8F79D6EC350");

	enum VTIndices implements VTableIndex {
		GET_DEBUG_STATE, //
		GET_CURRENT_POSITION, //
		GET_STACK, //
		SET_BREAKPOINT, //
		FIND_BREAKPOINT_BY_ID, //
		ENUMERATE_BREAKPOINTS, //
		GET_EVENT_FILTER, //
		SET_EVENT_FILTER, //
		START_DEBUGGING, //
		STOP_DEBUGGING, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT ScriptDebugState();

	HRESULT GetDebugState();

	HRESULT GetCurrentPosition(Pointer currentPosition, Pointer positionSpanEnd,
			BSTRByReference lineText);

	HRESULT GetStack(PointerByReference stack);

	HRESULT SetBreakpoint(ULONG linePosition, ULONG columnPosition, PointerByReference breakpoint);

	HRESULT FindBreakpointById(ULONGLONG breakpointId, PointerByReference breakpoint);

	HRESULT EnumerateBreakpoints(PointerByReference breakpointEnum);

	HRESULT GetEventFilter(ULONG eventFilter, BOOLByReference isBreakEnabled);

	HRESULT SetEventFilter(ULONG eventFilter, BOOL isBreakEnabled);

	HRESULT StartDebugging(Pointer debugClient);

	HRESULT StopDebugging(Pointer debugClient);

}
