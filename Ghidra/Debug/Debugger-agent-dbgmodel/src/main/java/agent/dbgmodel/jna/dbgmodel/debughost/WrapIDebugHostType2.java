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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

public class WrapIDebugHostType2 extends WrapIDebugHostType1 implements IDebugHostType2 {
	public static class ByReference extends WrapIDebugHostType2 implements Structure.ByReference {
	}

	public WrapIDebugHostType2() {
	}

	public WrapIDebugHostType2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT IsTypedef(BOOLByReference isTypedef) {
		return _invokeHR(VTIndices2.IS_TYPEDEF, getPointer(), isTypedef);
	}

	@Override
	public HRESULT GetTypedefBaseType(PointerByReference baseType) {
		return _invokeHR(VTIndices2.GET_TYPEDEF_BASE_TYPE, getPointer(), baseType);
	}

	@Override
	public HRESULT GetTypedefFinalBaseType(PointerByReference finalBaseType) {
		return _invokeHR(VTIndices2.GET_TYPEDEF_FINAL_BASE_TYPE, getPointer(), finalBaseType);
	}

	@Override
	public HRESULT GetFunctionVarArgsKind(ULONGByReference varArgsKind) {
		return _invokeHR(VTIndices2.GET_FUNCTION_VARARGS_KIND, getPointer(), varArgsKind);
	}  // VarArgsKind*

	@Override
	public HRESULT GetFunctionInstancePointerType(PointerByReference instancePointerType) {
		return _invokeHR(VTIndices2.GET_FUNCTION_INSTANCE_POINTER_TYPE, getPointer(),
			instancePointerType);
	}

}
