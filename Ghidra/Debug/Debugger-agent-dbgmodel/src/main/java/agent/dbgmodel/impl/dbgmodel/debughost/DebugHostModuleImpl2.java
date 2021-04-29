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

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.debughost.DebugHostModule2;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbol1;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostModule2;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostSymbol1;

public class DebugHostModuleImpl2 extends DebugHostModuleImpl1 implements DebugHostModule2 {
	private final IDebugHostModule2 jnaData;

	private long offset;

	public DebugHostModuleImpl2(IDebugHostModule2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DebugHostSymbol1 findContainingSymbolByRVA(long rva) {
		ULONGLONG ulRva = new ULONGLONG(rva);
		PointerByReference ppSymbol = new PointerByReference();
		ULONGLONGByReference pulOffset = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.FindContainingSymbolByRVA(ulRva, ppSymbol, pulOffset));

		offset = pulOffset.getValue().longValue();

		WrapIDebugHostSymbol1 wrap = new WrapIDebugHostSymbol1(ppSymbol.getValue());
		try {
			return DebugHostSymbolInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public long getOffset() {
		return offset;
	}

}
