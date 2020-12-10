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
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;
import agent.dbgeng.jna.dbgeng.event.IDebugEventContextCallbacks;

public interface IDebugClient6 extends IDebugClient5 {
	final IID IID_IDEBUG_CLIENT6 = new IID("fd28b4c5-c498-4686-a28e-62cad2154eb3");

	enum VTIndices6 implements VTableIndex {
		SET_EVENT_CONTEXT_CALLBACKS, //
		;

		static int start = VTableIndex.follow(VTIndices5.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT SetEventContextCallbacks(IDebugEventContextCallbacks Callbacks);
}
