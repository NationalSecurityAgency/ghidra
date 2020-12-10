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
package agent.dbgmodel.jna.dbgmodel.datamodel.script;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelScriptManager extends UnknownWithUtils
		implements IDataModelScriptManager {
	public static class ByReference extends WrapIDataModelScriptManager
			implements Structure.ByReference {
	}

	public WrapIDataModelScriptManager() {
	}

	public WrapIDataModelScriptManager(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetDefaultNameBinder(PointerByReference ppNameBinder) {
		return _invokeHR(VTIndices.GET_DEFAULT_NAME_BINDER, getPointer(), ppNameBinder);
	}

	@Override
	public HRESULT RegisterScriptProvider(Pointer provider) {
		return _invokeHR(VTIndices.REGISTER_SCRIPT_PROVIDER, provider);
	}

	@Override
	public HRESULT UnregisterScriptProvider(Pointer provider) {
		return _invokeHR(VTIndices.UNREGISTER_SCRIPT_PROVIDER, getPointer(), provider);
	}

	@Override
	public HRESULT FindProviderForScriptType(WString scriptType, PointerByReference provider) {
		return _invokeHR(VTIndices.FIND_PROVIDER_FOR_SCRIPT_TYPE, getPointer(), scriptType,
			provider);
	}

	@Override
	public HRESULT FindProviderForScriptExtension(WString scriptExternsion,
			PointerByReference provider) {
		return _invokeHR(VTIndices.FIND_PROVIDER_FOR_SCRIPT_EXTENSION, getPointer(),
			scriptExternsion, provider);
	}

	@Override
	public HRESULT EnumerateScriptProviders(PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_SCRIPT_PROVIDERS, getPointer(), enumerator);
	}

}
