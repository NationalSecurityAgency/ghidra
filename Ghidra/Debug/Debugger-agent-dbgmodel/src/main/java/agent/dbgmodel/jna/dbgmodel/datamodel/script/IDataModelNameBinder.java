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

public interface IDataModelNameBinder extends IUnknownEx {
	final IID IID_IDATA_MODEL_NAME_BINDER = new IID("AF352B7B-8292-4c01-B360-2DC3696C65E7");

	enum VTIndices implements VTableIndex {
		BIND_VALUE, //
		BIND_REFERENCE, //
		ENUMERATE_VALUES, //
		ENUMERATE_REFERENCES, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT BindValue(Pointer contextObject, WString name, PointerByReference value,
			PointerByReference metadata);

	HRESULT BindReference(Pointer contextObject, WString name, PointerByReference reference,
			PointerByReference metadata);

	HRESULT EnumerateValues(Pointer contextObject, PointerByReference enumerator);

	HRESULT EnumerateReferences(Pointer contextObject, PointerByReference enumerator);

}
