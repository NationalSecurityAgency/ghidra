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
package agent.dbgeng.jna.dbgeng.client;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient3 extends WrapIDebugClient2 implements IDebugClient3 {
	public static class ByReference extends WrapIDebugClient3 implements Structure.ByReference {
	}

	public WrapIDebugClient3() {
	}

	public WrapIDebugClient3(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetRunningProcessSystemIdByExecutableNameWide(ULONGLONG Server, WString ExeName,
			ULONG Flags, ULONGByReference Id) {
		return _invokeHR(VTIndices3.GET_RUNNING_PROCESS_SYSTEM_ID_BY_EXECUTABLE_NAME_WIDE,
			getPointer(), Server, ExeName, Flags, Id);
	}

	@Override
	public HRESULT GetRunningProcessDescriptionWide(ULONGLONG Server, ULONG SystemId, ULONG Flags,
			char[] ExeName, ULONG ExeNameSize, ULONGByReference ActualExeNameSize,
			char[] Description, ULONG DescriptionSize, ULONGByReference ActualDescriptionSize) {
		return _invokeHR(VTIndices3.GET_RUNNING_PROCESS_DESCRIPTION_WIDE, getPointer(), Server,
			SystemId, Flags, ExeName, ExeNameSize, ActualExeNameSize, Description, DescriptionSize,
			ActualDescriptionSize);
	}

	@Override
	public HRESULT CreateProcessWide(ULONGLONG Server, WString CommandLine, ULONG CreateFlags) {
		return _invokeHR(VTIndices3.CREATE_PROCESS_WIDE, getPointer(), Server, CommandLine,
			CreateFlags);
	}

	@Override
	public HRESULT CreateProcessAndAttachWide(ULONGLONG Server, WString CommandLine,
			ULONG CreateFlags, ULONG ProcessId, ULONG AttachFlags) {
		return _invokeHR(VTIndices3.CREATE_PROCESS_AND_ATTACH_WIDE, getPointer(), Server,
			CommandLine, CreateFlags, ProcessId, AttachFlags);
	}
}
