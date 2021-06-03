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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugClient7 extends IDebugClient6 {
	final IID IID_IDEBUG_CLIENT7 = new IID("13586be3-542e-481e-b1f2-8497ba74f9a9");

	enum VTIndices7 implements VTableIndex {
		SET_CLIENT_CONTEXT, //
		;

		static int start = VTableIndex.follow(VTIndices6.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT SetClientContext(Pointer Context, ULONG ContextSize);
}
