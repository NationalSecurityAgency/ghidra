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
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbol1;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostSymbolEnumerator;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostSymbol1;

public class DebugHostSymbolEnumeratorImpl implements DebugHostSymbolEnumeratorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostSymbolEnumerator jnaData;

	public DebugHostSymbolEnumeratorImpl(IDebugHostSymbolEnumerator jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void reset() {
		COMUtils.checkRC(jnaData.Reset());
	}

	@Override
	public DebugHostSymbol1 getNext() {
		PointerByReference ppSymbol = new PointerByReference();
		HRESULT hr = jnaData.GetNext(ppSymbol);
		if (hr.longValue() != 0) {
			return null;
		}
		/*
		if (hr.equals(COMUtilsExtra.E_BOUNDS)) {
			return null;
		}
		COMUtils.checkRC(hr);
		*/

		WrapIDebugHostSymbol1 wrap = new WrapIDebugHostSymbol1(ppSymbol.getValue());
		try {
			return DebugHostSymbolInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

}
