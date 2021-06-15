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

public class WrapIModelPropertyAccessor extends UnknownWithUtils implements IModelPropertyAccessor {
	public static class ByReference extends WrapIModelPropertyAccessor
			implements Structure.ByReference {
	}

	public WrapIModelPropertyAccessor() {
	}

	public WrapIModelPropertyAccessor(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetValue(WString key, Pointer contextObject, PointerByReference value) {
		return _invokeHR(VTIndices.GET_VALUE, getPointer(), key, contextObject, value);
	}

	@Override
	public HRESULT SetValue(WString key, Pointer contextObject, Pointer value) {
		return _invokeHR(VTIndices.SET_VALUE, getPointer(), key, contextObject, value);
	}

}
