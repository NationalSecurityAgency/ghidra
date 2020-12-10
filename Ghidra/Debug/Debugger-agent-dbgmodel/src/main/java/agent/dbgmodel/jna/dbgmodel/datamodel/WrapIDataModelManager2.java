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
package agent.dbgmodel.jna.dbgmodel.datamodel;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

public class WrapIDataModelManager2 extends WrapIDataModelManager1 implements IDataModelManager2 {
	public static class ByReference extends WrapIDataModelManager2
			implements Structure.ByReference {
	}

	public WrapIDataModelManager2() {
	}

	public WrapIDataModelManager2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT AcquireSubNamespace(WString modelName, WString subNamespaceModelName,
			WString accessName, Pointer metadata, PointerByReference namespaceModelObject) {
		return _invokeHR(VTIndices2.ACQUIRE_SUBNAMESPACE, getPointer(), modelName,
			subNamespaceModelName, accessName, metadata, namespaceModelObject);
	}

	@Override
	public HRESULT CreateTypedIntrinsicObjectEx(Pointer context, VARIANT.ByReference intrinsicData,
			Pointer type, PointerByReference object) {
		return _invokeHR(VTIndices2.CREATE_TYPED_INTRINSIC_OBJECT_EX, getPointer(), context,
			intrinsicData, type, object);
	}

}
