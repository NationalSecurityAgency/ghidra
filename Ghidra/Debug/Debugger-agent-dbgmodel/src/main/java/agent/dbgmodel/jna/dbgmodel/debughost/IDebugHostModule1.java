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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostModule1 extends IDebugHostBaseClass {
	final IID IID_IDEBUG_HOST_MODULE = new IID("C9BA3E18-D070-4378-BBD0-34613B346E1E");

	enum VTIndices1 implements VTableIndex {
		GET_IMAGE_NAME, //
		GET_BASE_LOCATION, //
		GET_VERSION, //
		FIND_TYPE_BY_NAME, //
		FIND_SYMBOL_BY_RVA, //
		FIND_SYMBOL_BY_NAME, //
		;

		public int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetImageName(BOOL allowPath, BSTRByReference imageName);

	HRESULT GetBaseLocation(LOCATION.ByReference moduleBaseLocation);

	HRESULT GetVersion(ULONGLONGByReference fileVersion, ULONGLONGByReference productVersion);

	HRESULT FindTypeByName(WString typeName, PointerByReference type);

	HRESULT FindSymbolByRVA(ULONGLONG rva, PointerByReference symbol);

	HRESULT FindSymbolByName(WString symbolName, PointerByReference symbol);

}
