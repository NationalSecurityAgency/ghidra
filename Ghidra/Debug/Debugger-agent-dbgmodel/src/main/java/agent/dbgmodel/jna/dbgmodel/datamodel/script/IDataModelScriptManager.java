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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelScriptManager extends IUnknownEx {
	final IID IID_IDATA_MODEL_SCRIPT_MANAGER = new IID("6FD11E33-E5AD-410b-8011-68C6BC4BF80D");

	enum VTIndices implements VTableIndex {
		GET_DEFAULT_NAME_BINDER, //
		REGISTER_SCRIPT_PROVIDER, //
		UNREGISTER_SCRIPT_PROVIDER, //
		FIND_PROVIDER_FOR_SCRIPT_TYPE, //
		FIND_PROVIDER_FOR_SCRIPT_EXTENSION, //
		ENUMERATE_SCRIPT_PROVIDERS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetDefaultNameBinder(PointerByReference ppNameBinder);

	HRESULT RegisterScriptProvider(Pointer provider);

	HRESULT UnregisterScriptProvider(Pointer provider);

	HRESULT FindProviderForScriptType(WString scriptType, PointerByReference provider);

	HRESULT FindProviderForScriptExtension(WString scriptExternsion, PointerByReference provider);

	HRESULT EnumerateScriptProviders(PointerByReference enumerator);

}
