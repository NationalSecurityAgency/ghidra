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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSystemObjects3 extends IDebugSystemObjects2 {
	final IID IID_IDEBUG_SYSTEM_OBJECTS3 = new IID("e9676e2f-e286-4ea3-b0f9-dfe5d9fc330e");

	enum VTIndices3 implements VTableIndex {
		GET_EVENT_SYSTEM, //
		GET_CURRENT_SYSTEM_ID, //
		SET_CURRENT_SYSTEM_ID, //
		GET_NUMBER_SYSTEMS, //
		GET_SYSTEM_IDS_BY_INDEX, //
		GET_TOTAL_NUMBER_THREADS_AND_PROCESSES, //
		GET_CURRENT_SYSTEM_SERER, //
		GET_SYSTEM_BY_SERVER, //
		GET_CURRENT_SYSTEM_SERVER_NAME, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetEventSystem(ULONGByReference Id);

	HRESULT GetCurrentSystemId(ULONGByReference Id);

	HRESULT SetCurrentSystemId(ULONG Id);

	HRESULT GetNumberSystems(ULONGByReference Number);

	HRESULT GetSystemIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds);
}
