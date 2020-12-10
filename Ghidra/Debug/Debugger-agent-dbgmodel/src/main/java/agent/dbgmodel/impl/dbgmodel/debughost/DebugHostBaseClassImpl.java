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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.SymbolKind;
import agent.dbgmodel.jna.dbgmodel.debughost.*;

public abstract class DebugHostBaseClassImpl implements DebugHostBaseClassInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostBaseClass jnaData;

	public DebugHostBaseClassImpl(IDebugHostBaseClass jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public DebugHostContext getContext() {
		PointerByReference ppContext = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContext(ppContext));

		WrapIDebugHostContext wrap = new WrapIDebugHostContext(ppContext.getValue());
		try {
			return DebugHostContextInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostSymbolEnumerator enumerateChildren(SymbolKind kind, WString name) {
		ULONG ulKind = new ULONG(kind.ordinal());
		PointerByReference ppEnum = new PointerByReference();
		HRESULT hr = jnaData.EnumerateChildren(ulKind, name, ppEnum);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDebugHostSymbolEnumerator wrap = new WrapIDebugHostSymbolEnumerator(ppEnum.getValue());
		try {
			return DebugHostSymbolEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public SymbolKind getSymbolKind() {
		ULONGByReference pulKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetSymbolKind(pulKind));
		return SymbolKind.values()[pulKind.getValue().intValue()];
	}

	@Override
	public String getName() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetName(bref));
		BSTR bstr = bref.getValue();
		String modelName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return modelName;
	}

	@Override
	public DebugHostType1 getType() {
		PointerByReference ppType = new PointerByReference();
		HRESULT hr = jnaData.GetType(ppType);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostModule1 getContainingModule() {
		PointerByReference ppType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContainingModule(ppType));

		WrapIDebugHostModule1 wrap = new WrapIDebugHostModule1(ppType.getValue());
		try {
			return DebugHostModuleInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public long getOffset() {
		ULONGLONGByReference ppOffset = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetOffset(ppOffset));
		return ppOffset.getValue().longValue();
	}

	@Override
	public IDebugHostBaseClass getJnaData() {
		return jnaData;
	}

}
