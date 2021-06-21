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
package agent.dbgmodel.jna.dbgmodel.main;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIKeyStore extends UnknownWithUtils implements IKeyStore {
	public static class ByReference extends WrapIKeyStore implements Structure.ByReference {
	}

	public WrapIKeyStore() {
	}

	public WrapIKeyStore(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetKey(WString key, PointerByReference object, PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT SetKey(WString key, Pointer object, Pointer metadata) {
		return _invokeHR(VTIndices.SET_KEY, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT GetKeyValue(WString key, PointerByReference object,
			PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY_VALUE, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT SetKeyValue(WString key, Pointer object) {
		return _invokeHR(VTIndices.SET_KEY_VALUE, getPointer(), key, object);
	}

	@Override
	public HRESULT ClearKeys() {
		return _invokeHR(VTIndices.CLEAR_KEYS, getPointer());
	}

}
