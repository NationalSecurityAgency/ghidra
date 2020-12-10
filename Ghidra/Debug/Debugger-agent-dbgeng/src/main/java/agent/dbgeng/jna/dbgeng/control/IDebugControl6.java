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
package agent.dbgeng.jna.dbgeng.control;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugControl6 extends IDebugControl5 {
	final IID IID_IDEBUG_CONTROL6 = new IID("bc0d583f-126d-43a1-9cc4-a860ab1d537b");

	enum VTIndices6 implements VTableIndex {
		GET_EXECUTABLE_STATUS_EX, //
		GET_SYNCHRONIZATION_STATUS, //
		;

		static int start = VTableIndex.follow(VTIndices5.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetExecutionStatusEx(ULONGByReference Status);
}
