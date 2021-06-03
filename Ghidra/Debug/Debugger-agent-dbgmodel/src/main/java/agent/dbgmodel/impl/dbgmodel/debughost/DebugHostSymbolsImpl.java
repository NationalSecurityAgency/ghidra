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
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.debughost.*;

public class DebugHostSymbolsImpl implements DebugHostSymbolsInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostSymbols jnaData;

	private LOCATION derivedLocation;

	public DebugHostSymbolsImpl(IDebugHostSymbols jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DebugHostModuleSignature createModuleSignature(WString pwszModuleName,
			WString pwszMinVersion, WString pwszMaxVersion) {
		PointerByReference ppModuleSignature = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateModuleSignature(pwszModuleName, pwszMinVersion,
			pwszMaxVersion, ppModuleSignature));

		WrapIDebugHostModuleSignature wrap =
			new WrapIDebugHostModuleSignature(ppModuleSignature.getValue());
		try {
			return DebugHostModuleSignatureInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostTypeSignature createTypeSignature(WString signatureSpecification,
			DebugHostModule1 module) {
		Pointer pModule = module == null ? null : module.getPointer();
		PointerByReference ppTypeSignature = new PointerByReference();
		COMUtils.checkRC(
			jnaData.CreateTypeSignature(signatureSpecification, pModule,
				ppTypeSignature));

		WrapIDebugHostTypeSignature wrap =
			new WrapIDebugHostTypeSignature(ppTypeSignature.getValue());
		try {
			return DebugHostTypeSignatureInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostTypeSignature createTypeSignatureForModuleRange(WString signatureSpecification,
			WString pwszModuleName, WString pwszMinVersion, WString pwszMaxVersion) {
		PointerByReference ppTypeSignature = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateTypeSignatureForModuleRange(signatureSpecification,
			pwszModuleName, pwszMinVersion, pwszMaxVersion, ppTypeSignature));

		WrapIDebugHostTypeSignature wrap =
			new WrapIDebugHostTypeSignature(ppTypeSignature.getValue());
		try {
			return DebugHostTypeSignatureInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostSymbolEnumerator enumerateModules(DebugHostContext context) {
		Pointer pContext = context.getPointer();
		PointerByReference moduleEnum = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateModules(pContext, moduleEnum));

		WrapIDebugHostSymbolEnumerator wrap =
			new WrapIDebugHostSymbolEnumerator(moduleEnum.getValue());
		try {
			return DebugHostSymbolEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostModule1 findModuleByName(DebugHostContext context, String moduleName) {
		Pointer pContext = context.getPointer();
		PointerByReference ppModule = new PointerByReference();
		COMUtils.checkRC(jnaData.FindModuleByName(pContext, new WString(moduleName), ppModule));

		WrapIDebugHostModule1 wrap = new WrapIDebugHostModule1(ppModule.getValue());
		try {
			return DebugHostModuleInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostModule1 findModuleByLocation(DebugHostContext context,
			LOCATION moduleLocation) {
		Pointer pContext = context.getPointer();
		PointerByReference ppModule = new PointerByReference();
		COMUtils.checkRC(jnaData.FindModuleByLocation(pContext, moduleLocation, ppModule));

		WrapIDebugHostModule1 wrap = new WrapIDebugHostModule1(ppModule.getValue());
		try {
			return DebugHostModuleInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostType1 getMostDerivedObject(DebugHostContext context, LOCATION location,
			DebugHostType1 objectType) {
		Pointer pContext = context.getPointer();
		Pointer pObjectType = objectType.getPointer();
		LOCATION.ByReference pDerivedLocation = new LOCATION.ByReference();
		PointerByReference ppDerivedType = new PointerByReference();
		COMUtils.checkRC(
			jnaData.GetMostDerivedObject(pContext, location, pObjectType, pDerivedLocation,
				ppDerivedType));

		derivedLocation = new LOCATION(pDerivedLocation);
		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppDerivedType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public LOCATION getDerivedLocation() {
		return derivedLocation;
	}

}
