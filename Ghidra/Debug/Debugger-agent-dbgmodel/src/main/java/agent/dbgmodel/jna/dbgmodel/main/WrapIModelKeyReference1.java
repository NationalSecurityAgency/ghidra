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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIModelKeyReference1 extends UnknownWithUtils implements IModelKeyReference {
	public static class ByReference extends WrapIModelKeyReference1
			implements Structure.ByReference {
	}

	public WrapIModelKeyReference1() {
	}

	public WrapIModelKeyReference1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetKeyName(BSTRByReference keyName) {
		return _invokeHR(VTIndices.GET_KEY_NAME, getPointer(), keyName);
	}

	@Override
	public HRESULT GetOriginalObject(PointerByReference originalObject) {
		return _invokeHR(VTIndices.GET_ORIGINAL_OBJECT, getPointer(), originalObject);
	}

	@Override
	public HRESULT GetContextObject(PointerByReference containingObject) {
		return _invokeHR(VTIndices.GET_CONTAINING_OBJECT, getPointer(), containingObject);
	}

	@Override
	public HRESULT GetKey(PointerByReference object, PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY, getPointer(), object, metadata);
	}

	@Override
	public HRESULT GetKeyValue(PointerByReference object, PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY_VALUE, getPointer(), object, metadata);
	}

	@Override
	public HRESULT SetKey(Pointer object, Pointer metadata) {
		return _invokeHR(VTIndices.SET_KEY, getPointer(), object, object, metadata);
	}

	@Override
	public HRESULT SetKeyValue(Pointer object) {
		return _invokeHR(VTIndices.SET_KEY_VALUE, getPointer(), object);
	}

}
