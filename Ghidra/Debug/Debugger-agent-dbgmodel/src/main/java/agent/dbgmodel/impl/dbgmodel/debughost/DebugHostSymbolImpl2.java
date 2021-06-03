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
package agent.dbgmodel.impl.dbgmodel.debughost;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbol2;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbolEnumerator;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostSymbol2;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostSymbolEnumerator;

public class DebugHostSymbolImpl2 extends DebugHostSymbolImpl1 implements DebugHostSymbol2 {
	private final IDebugHostSymbol2 jnaData;

	public DebugHostSymbolImpl2(IDebugHostSymbol2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DebugHostSymbolEnumerator enumerateChildrenEx(long kind, WString name,
			Structure.ByReference searchInfo) {
		ULONG ulKind = new ULONG(kind);
		PointerByReference ppEnum = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateChildrenEx(ulKind, name, searchInfo, ppEnum));

		WrapIDebugHostSymbolEnumerator wrap = new WrapIDebugHostSymbolEnumerator(ppEnum.getValue());
		try {
			return DebugHostSymbolEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public int getLanguage() {
		ULONGByReference pulKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetLanguage(pulKind));
		return pulKind.getValue().intValue();
	}

}
