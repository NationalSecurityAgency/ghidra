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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelScriptDebugBreakpoint extends UnknownWithUtils
		implements IDataModelScriptDebugBreakpoint {
	public static class ByReference extends WrapIDataModelScriptDebugBreakpoint
			implements Structure.ByReference {
	}

	public WrapIDataModelScriptDebugBreakpoint() {
	}

	public WrapIDataModelScriptDebugBreakpoint(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetId() {
		return _invokeHR(VTIndices.GET_ID, getPointer());
	}

	@Override
	public HRESULT IsEnabled() {
		return _invokeHR(VTIndices.IS_ENABLED, getPointer());
	}

	@Override
	public HRESULT Enable() {
		return _invokeHR(VTIndices.ENABLE, getPointer());
	}

	@Override
	public HRESULT Disable() {
		return _invokeHR(VTIndices.DISABLE, getPointer());
	}

	@Override
	public HRESULT Remove() {
		return _invokeHR(VTIndices.REMOVE, getPointer());
	}

	@Override
	public HRESULT GetPosition(Pointer position, Pointer positionSpanEnd, WString lineText) {
		return _invokeHR(VTIndices.GET_POSITION, getPointer(), position, positionSpanEnd, lineText);
	}

}
