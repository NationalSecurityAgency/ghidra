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
package agent.dbgmodel.jna.dbgmodel.concept;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDynamicKeyProviderConcept extends IUnknownEx {
	final IID IID_IDYNAMIC_KEY_PROVIDER_CONCEPT = new IID("E7983FA1-80A7-498c-988F-518DDC5D4025");

	enum VTIndices implements VTableIndex {
		GET_KEY, //
		SET_KEY, //
		ENUMERATE_KEYS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetKey(Pointer contextObject, WString key, PointerByReference keyValue,
			PointerByReference metadata, BOOLByReference hasKey);

	HRESULT SetKey(Pointer contextObject, WString key, Pointer keyValue, Pointer metadata);

	HRESULT EnumerateKeys(Pointer contextObject, PointerByReference ppEnumerator);

}
