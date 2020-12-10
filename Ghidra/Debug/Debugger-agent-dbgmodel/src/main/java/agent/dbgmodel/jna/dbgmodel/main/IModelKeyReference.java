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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IModelKeyReference extends IUnknownEx {
	final IID IID_IMODEL_REFERENCE = new IID("5253DCF8-5AFF-4c62-B302-56A289E00998");

	enum VTIndices implements VTableIndex {
		GET_KEY_NAME, //
		GET_ORIGINAL_OBJECT, //
		GET_CONTAINING_OBJECT, //
		GET_KEY, //
		GET_KEY_VALUE, //
		SET_KEY, //
		SET_KEY_VALUE, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetKeyName(BSTRByReference keyName);

	HRESULT GetOriginalObject(PointerByReference originalObject);

	HRESULT GetContextObject(PointerByReference containingObject);

	HRESULT GetKey(PointerByReference object, PointerByReference metadata);

	HRESULT GetKeyValue(PointerByReference object, PointerByReference metadata);

	HRESULT SetKey(Pointer object, Pointer metadata);

	HRESULT SetKeyValue(Pointer object);

}
