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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostTypeSignature extends IUnknownEx {
	final IID IID_IDEBUG_HOST_TYPE_SIGNATURE = new IID("3AADC353-2B14-4abb-9893-5E03458E07EE");

	enum VTIndices implements VTableIndex {
		GET_HASH_CODE, //
		IS_MATCH, //
		COMPARE_AGAINST;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetHashCode(ULONGByReference hashCode);

	HRESULT IsMatch(Pointer type, BOOLByReference isMatch, PointerByReference wildcardMatches);

	HRESULT CompareAgainst(Pointer typeSignature, ULONGByReference result);

}
