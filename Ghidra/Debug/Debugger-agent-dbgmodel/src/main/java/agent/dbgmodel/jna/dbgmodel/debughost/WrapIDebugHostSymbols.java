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
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

public class WrapIDebugHostSymbols extends UnknownWithUtils implements IDebugHostSymbols {
	public static class ByReference extends WrapIDebugHostSymbols implements Structure.ByReference {
	}

	public WrapIDebugHostSymbols() {
	}

	public WrapIDebugHostSymbols(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT CreateModuleSignature(WString pwszModuleName, WString pwszMinVersion,
			WString pwszMaxVersion, PointerByReference ppModuleSignature) {
		return _invokeHR(VTIndices.CREATE_MODULE_SIGNATURE, getPointer(), pwszModuleName,
			pwszMinVersion, pwszMaxVersion, ppModuleSignature);
	}

	@Override
	public HRESULT CreateTypeSignature(WString signatureSpecification, Pointer module,
			PointerByReference typeSignature) {
		return _invokeHR(VTIndices.CREATE_TYPE_SIGNATURE, getPointer(), signatureSpecification,
			module, typeSignature);
	}

	@Override
	public HRESULT CreateTypeSignatureForModuleRange(WString signatureSpecification,
			WString moduleName,
			WString minVersion, WString maxVersion, PointerByReference typeSignature) {
		return _invokeHR(VTIndices.CREATE_TYPE_SIGNATURE_FOR_MODULE_RANGE, getPointer(),
			signatureSpecification, moduleName, minVersion, maxVersion, typeSignature);
	}

	@Override
	public HRESULT EnumerateModules(Pointer context, PointerByReference moduleEnum) {
		return _invokeHR(VTIndices.ENUMERATE_MODULES, getPointer(), context, moduleEnum);
	}

	@Override
	public HRESULT FindModuleByName(Pointer context, WString moduleName,
			PointerByReference module) {
		return _invokeHR(VTIndices.FIND_MODULE_BY_NAME, getPointer(), context, moduleName, module);
	}

	@Override
	public HRESULT FindModuleByLocation(Pointer context, LOCATION moduleLocation,
			PointerByReference module) {
		return _invokeHR(VTIndices.FIND_MODULE_BY_LOCATION, getPointer(), context, moduleLocation,
			module);
	}

	@Override
	public HRESULT GetMostDerivedObject(Pointer pContext, LOCATION location, Pointer objectType,
			LOCATION.ByReference derivedLocation, PointerByReference derivedType) {
		return _invokeHR(VTIndices.GET_MOST_DERIVED_OBJECT, getPointer(), pContext, location,
			objectType, derivedLocation, derivedType);
	}

}
