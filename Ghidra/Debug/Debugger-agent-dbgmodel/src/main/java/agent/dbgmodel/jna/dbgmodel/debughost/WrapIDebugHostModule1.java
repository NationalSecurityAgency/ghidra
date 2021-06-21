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

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

public class WrapIDebugHostModule1 extends WrapIDebugHostBaseClass implements IDebugHostModule1 {
	public static class ByReference extends WrapIDebugHostModule1 implements Structure.ByReference {
	}

	public WrapIDebugHostModule1() {
	}

	public WrapIDebugHostModule1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetImageName(BOOL allowPath, BSTRByReference imageName) {
		return _invokeHR(VTIndices1.GET_IMAGE_NAME, getPointer(), allowPath, imageName);
	}

	@Override
	public HRESULT GetBaseLocation(LOCATION.ByReference moduleBaseLocation) {
		return _invokeHR(VTIndices1.GET_BASE_LOCATION, getPointer(), moduleBaseLocation);
	}

	@Override
	public HRESULT GetVersion(ULONGLONGByReference fileVersion,
			ULONGLONGByReference productVersion) {
		return _invokeHR(VTIndices1.GET_VERSION, getPointer(), fileVersion, productVersion);
	}

	@Override
	public HRESULT FindTypeByName(WString typeName, PointerByReference type) {
		return _invokeHR(VTIndices1.FIND_TYPE_BY_NAME, getPointer(), typeName, type);
	}

	@Override
	public HRESULT FindSymbolByRVA(ULONGLONG rva, PointerByReference symbol) {
		return _invokeHR(VTIndices1.FIND_SYMBOL_BY_RVA, getPointer(), symbol);
	}

	@Override
	public HRESULT FindSymbolByName(WString symbolName, PointerByReference symbol) {
		return _invokeHR(VTIndices1.FIND_SYMBOL_BY_NAME, getPointer(), symbolName, symbol);
	}

}
