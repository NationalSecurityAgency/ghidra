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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHost extends IUnknownEx {
	final IID IID_IDEBUG_HOST = new IID("B8C74943-6B2C-4eeb-B5C5-35D378A6D99D");

	enum VTIndices implements VTableIndex {
		GET_HOST_DEFINED_INTERFACE, //
		GET_CURRENT_CONTEXT, //
		GET_DEFAULT_METADATA;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetHostDefinedInterface(PointerByReference hostUnk);

	HRESULT GetCurrentContext(PointerByReference context);

	HRESULT GetDefaultMetadata(PointerByReference defaultMetadataStore);

}
