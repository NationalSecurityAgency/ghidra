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

import com.sun.jna.Structure.ByReference;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostSymbol2 extends IDebugHostSymbol1 {
	final IID IID_IDEBUG_HOST_SYMBOL2 = new IID("21515B67-6720-4257-8A68-077DC944471C");

	enum VTIndices2 implements VTableIndex {
		ENUMERATE_CHILDREN_EX, //
		;

		public int start = VTableIndex.follow(VTIndices1.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT EnumerateChildrenEx(ULONG ulKind, WString name, ByReference searchInfo,
			PointerByReference ppEnum);

	HRESULT GetLanguage(ULONGByReference pKind);

}
