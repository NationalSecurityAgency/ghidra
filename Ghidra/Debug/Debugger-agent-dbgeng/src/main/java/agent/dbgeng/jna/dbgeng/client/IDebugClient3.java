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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugClient3 extends IDebugClient2 {
	final IID IID_IDEBUG_CLIENT3 = new IID("dd492d7f-71b8-4ad6-a8dc-1c887479ff91");

	enum VTIndices3 implements VTableIndex {
		GET_RUNNING_PROCESS_SYSTEM_ID_BY_EXECUTABLE_NAME_WIDE, //
		GET_RUNNING_PROCESS_DESCRIPTION_WIDE, //
		CREATE_PROCESS_WIDE, //
		CREATE_PROCESS_AND_ATTACH_WIDE, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetRunningProcessSystemIdByExecutableNameWide(ULONGLONG Server, WString ExeName,
			ULONG Flags, ULONGByReference Id);

	HRESULT GetRunningProcessDescriptionWide(ULONGLONG Server, ULONG SystemId, ULONG Flags,
			char[] ExeName, ULONG ExeNameSize, ULONGByReference ActualExeNameSize,
			char[] Description, ULONG DescriptionSize, ULONGByReference ActualDescriptionSize);

	HRESULT CreateProcessWide(ULONGLONG Server, WString CommandLine, ULONG CreateFlags);

	HRESULT CreateProcessAndAttachWide(ULONGLONG Server, WString CommandLine, ULONG CreateFlags,
			ULONG ProcessId, ULONG AttachFlags);
}
