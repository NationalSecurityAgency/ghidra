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
package agent.dbgeng.jna.dbgeng.dataspaces;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;
import agent.dbgeng.jna.dbgeng.WinNTExtra.MEMORY_BASIC_INFORMATION64;

public interface IDebugDataSpaces2 extends IDebugDataSpaces {
	final IID IID_IDEBUG_DATA_SPACES2 = new IID("7a5e852f-96e9-468f-ac1b-0b3addc4a049");

	enum VTIndices2 implements VTableIndex {
		VIRTUAL_TO_PHYSICAL, //
		GET_VIRTUAL_TRANSLATION_PHYSICAL_OFFSETS, //
		READ_HANDLE_DATA, //
		FILL_VIRTUAL, //
		FILL_PHYSICAL, //
		QUERY_VIRTUAL, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT QueryVirtual(ULONGLONG Offset, MEMORY_BASIC_INFORMATION64.ByReference Info);
}
