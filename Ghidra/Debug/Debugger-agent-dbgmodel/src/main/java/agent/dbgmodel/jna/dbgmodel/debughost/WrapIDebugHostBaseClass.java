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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHostBaseClass extends UnknownWithUtils implements IDebugHostBaseClass {
	public static class ByReference extends WrapIDebugHostBaseClass
			implements Structure.ByReference {
	}

	public WrapIDebugHostBaseClass() {
	}

	public WrapIDebugHostBaseClass(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetContext(PointerByReference context) {
		return _invokeHR(VTIndices.GET_CONTEXT, getPointer(), context);
	}

	@Override
	public HRESULT EnumerateChildren(ULONG kind, WString name, PointerByReference ppEnum) {
		return _invokeHR(VTIndices.ENUMERATE_CHILDREN, getPointer(), kind, name, ppEnum);
	}

	@Override
	public HRESULT GetSymbolKind(ULONGByReference kind) {
		return _invokeHR(VTIndices.GET_SYMBOL_KIND, getPointer(), kind);
	}

	@Override
	public HRESULT GetName(BSTRByReference symbolName) {
		return _invokeHR(VTIndices.GET_NAME, getPointer(), symbolName);
	}

	@Override
	public HRESULT GetType(PointerByReference type) {
		return _invokeHR(VTIndices.GET_TYPE, getPointer(), type);
	}

	@Override
	public HRESULT GetContainingModule(PointerByReference containingModule) {
		return _invokeHR(VTIndices.GET_CONTAINING_MODULE, getPointer(), containingModule);
	}

	@Override
	public HRESULT GetOffset(ULONGLONGByReference offset) {
		return _invokeHR(VTIndices.GET_OFFSET, getPointer(), offset);
	}

}
