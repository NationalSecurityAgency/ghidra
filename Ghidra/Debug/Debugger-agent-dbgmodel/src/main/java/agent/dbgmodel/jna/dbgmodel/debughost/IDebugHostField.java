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
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostField extends IDebugHostBaseClass {
	final IID IID_IDEBUG_HOST_FIELD = new IID("E06F6495-16BC-4cc9-B11D-2A6B23FA72F3");

	enum VTIndicesX implements VTableIndex {
		GET_LOCATION_KIND, //
		GET_OFFSET, //
		GET_LOCATION, //
		GET_VALUE, //		
		;

		public int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetLocationKind(ULONGByReference locationKind);  // LocationKind*

	HRESULT GetOffset(ULONGLONGByReference offset);

	HRESULT GetLocation(LOCATION.ByReference location);

	HRESULT GetValue(VARIANT.ByReference value);

}
