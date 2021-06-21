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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostSymbols extends IUnknownEx {
	final IID IID_IDEBUG_HOST_SYMBOLS = new IID("854FD751-C2E1-4eb2-B525-6619CB97A588");

	enum VTIndices implements VTableIndex {
		CREATE_MODULE_SIGNATURE, //
		CREATE_TYPE_SIGNATURE, //
		CREATE_TYPE_SIGNATURE_FOR_MODULE_RANGE, //
		ENUMERATE_MODULES, //
		FIND_MODULE_BY_NAME, //
		FIND_MODULE_BY_LOCATION, //
		GET_MOST_DERIVED_OBJECT, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT CreateModuleSignature(WString pwszModuleName, WString pwszMinVersion,
			WString pwszMaxVersion, PointerByReference ppModuleSignature);

	HRESULT CreateTypeSignature(WString signatureSpecification, Pointer module,
			PointerByReference typeSignature);

	HRESULT CreateTypeSignatureForModuleRange(WString signatureSpecification, WString moduleName,
			WString minVersion, WString maxVersion, PointerByReference typeSignature);

	HRESULT EnumerateModules(Pointer context, PointerByReference moduleEnum);

	HRESULT FindModuleByName(Pointer context, WString moduleName, PointerByReference module);

	HRESULT FindModuleByLocation(Pointer context, LOCATION moduleLocation,
			PointerByReference module);

	HRESULT GetMostDerivedObject(Pointer pContext, LOCATION location, Pointer objectType,
			LOCATION.ByReference derivedLocation, PointerByReference derivedType);

}
