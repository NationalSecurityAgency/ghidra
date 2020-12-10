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

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostBaseClass extends IUnknownEx {
	final IID IID_IDEBUG_HOST_BASE_CLASS = new IID("B94D57D2-390B-40f7-B5B4-B6DB897D974B");

	enum VTIndices implements VTableIndex {
		GET_CONTEXT, //
		ENUMERATE_CHILDREN, //
		GET_SYMBOL_KIND, //
		GET_NAME, //
		GET_TYPE, //
		GET_CONTAINING_MODULE, //
		GET_OFFSET, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetContext(PointerByReference context);

	HRESULT EnumerateChildren(ULONG kind, WString name, PointerByReference ppEnum);  // SymbolKind

	HRESULT GetSymbolKind(ULONGByReference kind); // SymbolKind*

	HRESULT GetName(BSTRByReference symbolName);  //?

	HRESULT GetType(PointerByReference type);

	HRESULT GetContainingModule(PointerByReference containingModule);

	HRESULT GetOffset(ULONGLONGByReference offset);

}
