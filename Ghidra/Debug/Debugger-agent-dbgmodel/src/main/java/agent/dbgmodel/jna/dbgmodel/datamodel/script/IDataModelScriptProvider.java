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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelScriptProvider extends IUnknownEx {
	final IID IID_IDATA_MODEL_SCRIPT_PROVIDER = new IID("513461E0-4FCA-48ce-8658-32F3E2056F3B");

	enum VTIndices implements VTableIndex {
		GET_NAME, //
		GET_EXTENSION, //
		CREATE_SCRIPT, //
		GET_DEFAULT_TEMPLATE_CONTENT, //
		ENUMERATE_TEMPLATES, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetName(BSTRByReference name);

	HRESULT GetExtension(BSTRByReference extension);

	HRESULT CreateScript(PointerByReference script);

	HRESULT GetDefaultTemplateContent(PointerByReference templateContent);

	HRESULT EnumerateTemplates(PointerByReference enumerator);

}
