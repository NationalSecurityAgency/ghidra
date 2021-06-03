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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugClient2 extends IDebugClient {
	final IID IID_IDEBUG_CLIENT2 = new IID("edbed635-372e-4dab-bbfe-ed0d2f63be81");

	enum VTIndices2 implements VTableIndex {
		WRITE_DUMP_FILE2, //
		ADD_DUMP_INFORMATION_FILE, //
		END_PROCESS_SERVER, //
		WAIT_FOR_PROCESS_SERVER_END, //
		IS_KERNEL_DEBUGGER_ENABLED, //
		TERMINATE_CURRENT_PROCESS, //
		DETACH_CURRENT_PROCESS, //
		ABANDON_CURRENT_PROCESS, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT WriteDumpFile2(String DumpFile, ULONG Qualifier, ULONG FormatFlags, String Comment);

	HRESULT AddDumpInformationFile(String InfoFile, ULONG Type);

	HRESULT EndProcessServer(ULONGLONG Server);

	HRESULT WaitForProcessServerEnd(ULONG Timeout);

	HRESULT IsKernelDebuggerEnabled();

	HRESULT TerminateCurrentProcess();

	HRESULT DetachCurrentProcess();

	HRESULT AbandonCurrentProcess();
}
