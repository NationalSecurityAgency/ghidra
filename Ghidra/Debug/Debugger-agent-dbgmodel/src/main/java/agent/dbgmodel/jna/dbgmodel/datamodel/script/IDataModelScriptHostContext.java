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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelScriptHostContext extends IUnknownEx {
	final IID IID_IDATA_MODEL_SCRIPT_HOST_CONTEXT = new IID("014D366A-1F23-4981-9219-B2DB8B402054");

	enum VTIndices implements VTableIndex {
		NOTIFY_SCRIPT_CHANGE, //
		GET_NAMESPACE_OBJECT, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT NotifyScriptChange(Pointer script, ULONG changeKind);

	HRESULT GetNamespaceObject(PointerByReference namespaceObject);

}
