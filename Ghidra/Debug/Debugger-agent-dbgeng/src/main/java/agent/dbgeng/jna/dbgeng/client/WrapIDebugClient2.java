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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient2 extends WrapIDebugClient implements IDebugClient2 {
	public static class ByReference extends WrapIDebugClient2 implements Structure.ByReference {
	}

	public WrapIDebugClient2() {
	}

	public WrapIDebugClient2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT WriteDumpFile2(String DumpFile, ULONG Qualifier, ULONG FormatFlags,
			String Comment) {
		return _invokeHR(VTIndices2.WRITE_DUMP_FILE2, getPointer(), DumpFile, Qualifier,
			FormatFlags, Comment);
	}

	@Override
	public HRESULT AddDumpInformationFile(String InfoFile, ULONG Type) {
		return _invokeHR(VTIndices2.ADD_DUMP_INFORMATION_FILE, getPointer(), InfoFile, Type);
	}

	@Override
	public HRESULT EndProcessServer(ULONGLONG Server) {
		return _invokeHR(VTIndices2.END_PROCESS_SERVER, getPointer(), Server);
	}

	@Override
	public HRESULT WaitForProcessServerEnd(ULONG Timeout) {
		return _invokeHR(VTIndices2.WAIT_FOR_PROCESS_SERVER_END, getPointer(), Timeout);
	}

	@Override
	public HRESULT IsKernelDebuggerEnabled() {
		return _invokeHR(VTIndices2.IS_KERNEL_DEBUGGER_ENABLED, getPointer());
	}

	@Override
	public HRESULT TerminateCurrentProcess() {
		return _invokeHR(VTIndices2.TERMINATE_CURRENT_PROCESS, getPointer());
	}

	@Override
	public HRESULT DetachCurrentProcess() {
		return _invokeHR(VTIndices2.DETACH_CURRENT_PROCESS, getPointer());
	}

	@Override
	public HRESULT AbandonCurrentProcess() {
		return _invokeHR(VTIndices2.ABANDON_CURRENT_PROCESS, getPointer());
	}
}
