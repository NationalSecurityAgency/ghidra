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
package agent.dbgeng.jna.dbgeng.advanced;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

import com.sun.jna.platform.win32.COM.IUnknown;

public interface IDebugAdvanced extends IUnknown {
	final IID IID_IDEBUG_ADVANCED = new IID("f2df5f53-071f-47bd-9de6-5734c3fed689");

	enum VTIndices implements VTableIndex {
		GET_THREAD_CONTEXT, //
		SET_THREAD_CONTEXT, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetThreadContext(Pointer Context, ULONG ContextSize);

	HRESULT SetThreadContext(Pointer Context, ULONG ContextSize);
}
