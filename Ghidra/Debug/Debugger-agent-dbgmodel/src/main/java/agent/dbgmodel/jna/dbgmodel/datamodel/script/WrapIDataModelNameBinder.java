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

public class WrapIDataModelNameBinder extends UnknownWithUtils implements IDataModelNameBinder {
	public static class ByReference extends WrapIDataModelNameBinder
			implements Structure.ByReference {
	}

	public WrapIDataModelNameBinder() {
	}

	public WrapIDataModelNameBinder(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT BindValue(Pointer contextObject, WString name, PointerByReference value,
			PointerByReference metadata) {
		return _invokeHR(VTIndices.BIND_VALUE, getPointer(), contextObject, name, value, metadata);
	}

	@Override
	public HRESULT BindReference(Pointer contextObject, WString name, PointerByReference reference,
			PointerByReference metadata) {
		return _invokeHR(VTIndices.BIND_REFERENCE, getPointer(), contextObject, name, reference,
			metadata);
	}

	@Override
	public HRESULT EnumerateValues(Pointer contextObject, PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_VALUES, getPointer(), contextObject, enumerator);
	}

	@Override
	public HRESULT EnumerateReferences(Pointer contextObject, PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_REFERENCES, getPointer(), contextObject, enumerator);
	}

}
