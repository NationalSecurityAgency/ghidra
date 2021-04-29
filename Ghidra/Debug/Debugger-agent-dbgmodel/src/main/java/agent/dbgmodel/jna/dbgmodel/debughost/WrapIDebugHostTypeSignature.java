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

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHostTypeSignature extends UnknownWithUtils
		implements IDebugHostTypeSignature {
	public static class ByReference extends WrapIDebugHostTypeSignature
			implements Structure.ByReference {
	}

	public WrapIDebugHostTypeSignature() {
	}

	public WrapIDebugHostTypeSignature(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetHashCode(ULONGByReference hashCode) {
		return _invokeHR(VTIndices.GET_HASH_CODE, getPointer(), hashCode);
	}

	@Override
	public HRESULT IsMatch(Pointer type, BOOLByReference isMatch,
			PointerByReference wildcardMatches) {
		return _invokeHR(VTIndices.IS_MATCH, getPointer(), type, isMatch, wildcardMatches);
	}

	@Override
	public HRESULT CompareAgainst(Pointer typeSignature, ULONGByReference result) {
		return _invokeHR(VTIndices.COMPARE_AGAINST, getPointer(), typeSignature, result);
	}

}
