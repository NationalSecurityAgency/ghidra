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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbol1;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.debughost.*;

public class DebugHostModuleImpl1 extends DebugHostBaseClassImpl
		implements DebugHostModuleInternal {
	@SuppressWarnings("unused")
	private final IDebugHostModule1 jnaData;
	private long fileVersion;
	private long productVersion;

	public DebugHostModuleImpl1(IDebugHostModule1 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public String getImageName(boolean allowPath) {
		BOOL bAllowPath = new BOOL(allowPath);
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetImageName(bAllowPath, bref));
		BSTR bstr = bref.getValue();
		String imageName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return imageName;
	}

	@Override
	public LOCATION getBaseLocation() {
		LOCATION.ByReference pLocation = new LOCATION.ByReference();
		COMUtils.checkRC(jnaData.GetBaseLocation(pLocation));
		return new LOCATION(pLocation);
	}

	@Override
	public void getVersion() {
		ULONGLONGByReference pulFileVersion = new ULONGLONGByReference();
		ULONGLONGByReference pulProductVersion = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetVersion(pulFileVersion, pulProductVersion));
		fileVersion = pulFileVersion.getValue().longValue();
		productVersion = pulProductVersion.getValue().longValue();
	}

	@Override
	public DebugHostType1 findTypeByName(String typeName) {
		PointerByReference ppType = new PointerByReference();
		HRESULT hr = jnaData.FindTypeByName(new WString(typeName), ppType);
		if (hr.equals(COMUtilsExtra.E_FAIL) || hr.equals(COMUtilsExtra.E_BOUNDS)) {
			System.out.println(typeName + " NOT FOUND");
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
	public DebugHostSymbol1 findSymbolByRVA(long rva) {
		ULONGLONG ulRva = new ULONGLONG(rva);
		PointerByReference ppSymbol = new PointerByReference();
		HRESULT hr = jnaData.FindSymbolByRVA(ulRva, ppSymbol);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			System.out.println(rva + " NOT FOUND");
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDebugHostSymbol1 wrap = new WrapIDebugHostSymbol1(ppSymbol.getValue());
		try {
			return DebugHostSymbolInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostSymbol1 findSymbolByName(String symbolName) {
		PointerByReference ppSymbol = new PointerByReference();
		HRESULT hr = jnaData.FindSymbolByName(new WString(symbolName), ppSymbol);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			System.out.println(symbolName + " NOT FOUND");
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDebugHostSymbol1 wrap = new WrapIDebugHostSymbol1(ppSymbol.getValue());
		try {
			return DebugHostSymbolInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public long getFileVersion() {
		return fileVersion;
	}

	public long getProductVersion() {
		return productVersion;
	}

	@Override
	public DebugHostSymbol1 asSymbol() {
		return DebugHostSymbolInternal.tryPreferredInterfaces(jnaData::QueryInterface);
	}

}
