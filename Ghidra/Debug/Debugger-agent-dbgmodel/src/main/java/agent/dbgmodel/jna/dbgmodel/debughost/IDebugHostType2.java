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
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostType2 extends IDebugHostType1 {
	final IID IID_IDEBUG_HOST_TYPE2 = new IID("B28632B9-8506-4676-87CE-8F7E05E59876");

	enum VTIndices2 implements VTableIndex {
		IS_TYPEDEF, //
		GET_TYPEDEF_BASE_TYPE, //
		GET_TYPEDEF_FINAL_BASE_TYPE, //
		GET_FUNCTION_VARARGS_KIND, //
		GET_FUNCTION_INSTANCE_POINTER_TYPE, //
		;

		public int start = VTableIndex.follow(VTIndices1.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT IsTypedef(BOOLByReference isTypedef);

	HRESULT GetTypedefBaseType(PointerByReference baseType);

	HRESULT GetTypedefFinalBaseType(PointerByReference finalBaseType);

	HRESULT GetFunctionVarArgsKind(ULONGByReference varArgsKind);  // VarArgsKind*

	HRESULT GetFunctionInstancePointerType(PointerByReference instancePointerType);

}
