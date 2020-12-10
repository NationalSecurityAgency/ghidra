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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IKeyStore extends IUnknownEx {
	final IID IID_IKEY_STORE = new IID("0FC7557D-401D-4fca-9365-DA1E9850697C");

	enum VTIndices implements VTableIndex {
		GET_KEY, //
		SET_KEY, //
		GET_KEY_VALUE, //
		SET_KEY_VALUE, //
		CLEAR_KEYS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetKey(WString key, PointerByReference object, PointerByReference metadata);

	HRESULT SetKey(WString key, Pointer object, Pointer metadata);

	HRESULT GetKeyValue(WString key, PointerByReference object, PointerByReference metadata);

	HRESULT SetKeyValue(WString key, Pointer object);

	HRESULT ClearKeys();

}
