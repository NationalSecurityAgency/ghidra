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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelManager2 extends IDataModelManager1 {
	final IID IID_IDATA_MODEL_MANAGER2 = new IID("F412C5EA-2284-4622-A660-A697160D3312");

	enum VTIndices2 implements VTableIndex {
		ACQUIRE_SUBNAMESPACE, //
		CREATE_TYPED_INTRINSIC_OBJECT_EX, //
		;

		public int start = VTableIndex.follow(VTIndices1.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT AcquireSubNamespace(WString modelName, WString subNamespaceModelName,
			WString accessName, Pointer metadata, PointerByReference namespaceModelObject);

	HRESULT CreateTypedIntrinsicObjectEx(Pointer context, VARIANT.ByReference intrinsicData,
			Pointer type, PointerByReference object);

}
