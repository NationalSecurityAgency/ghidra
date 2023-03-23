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
package agent.dbgeng.jna.dbgeng.sysobj;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.sysobj.IDebugSystemObjects2.VTIndices2;

public class WrapIDebugSystemObjects2 extends WrapIDebugSystemObjects
		implements IDebugSystemObjects2 {
	public static class ByReference extends WrapIDebugSystemObjects2
			implements Structure.ByReference {
	}

	public WrapIDebugSystemObjects2() {
	}

	public WrapIDebugSystemObjects2(Pointer pvInstance) {
		super(pvInstance);
	}
	
	@Override
	public HRESULT GetImplicitThreadDataOffset(ULONGLONGByReference SysOffset) {
		return _invokeHR(VTIndices2.GET_IMPLICIT_THREAD_DATA_OFFSET, getPointer(), SysOffset);
	}

	@Override
	public HRESULT GetImplicitProcessDataOffset(ULONGLONGByReference SysOffset) {
		return _invokeHR(VTIndices2.GET_IMPLICIT_PROCESS_DATA_OFFSET, getPointer(), SysOffset);
	}
	
	@Override
	public HRESULT SetImplicitThreadDataOffset(ULONGLONG SysOffset) {
		return _invokeHR(VTIndices2.SET_IMPLICIT_THREAD_DATA_OFFSET, getPointer(), SysOffset);
	}

	@Override
	public HRESULT SetImplicitProcessDataOffset(ULONGLONG SysOffset) {
		return _invokeHR(VTIndices2.SET_IMPLICIT_PROCESS_DATA_OFFSET, getPointer(), SysOffset);
	}
	
}
