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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostModule2 extends IDebugHostModule1 {
	final IID IID_IDEBUG_HOST_MODULE2 = new IID("B51887E8-BCD0-4e8f-A8C7-434398B78C37");

	enum VTIndices2 implements VTableIndex {
		FIND_CONTAINING_SYMBOL_BY_RVA, //
		;

		public int start = VTableIndex.follow(VTIndices1.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT FindContainingSymbolByRVA(ULONGLONG rva, PointerByReference symbol,
			ULONGLONGByReference offset);

}
