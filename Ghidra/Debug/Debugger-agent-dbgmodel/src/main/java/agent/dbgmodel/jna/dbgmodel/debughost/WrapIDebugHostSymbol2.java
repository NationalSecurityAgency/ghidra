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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

public class WrapIDebugHostSymbol2 extends WrapIDebugHostSymbol1 implements IDebugHostSymbol2 {
	public static class ByReference extends WrapIDebugHostSymbol2 implements Structure.ByReference {
	}

	public WrapIDebugHostSymbol2() {
	}

	public WrapIDebugHostSymbol2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT EnumerateChildrenEx(ULONG kind, WString name,
			com.sun.jna.Structure.ByReference searchInfo,
			PointerByReference ppEnum) {
		return _invokeHR(VTIndices2.ENUMERATE_CHILDREN_EX, getPointer(), kind, name, searchInfo,
			ppEnum);
	}

	@Override
	public HRESULT GetLanguage(ULONGByReference pKind) {
		// TODO Auto-generated method stub
		return null;
	}

}
