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
package agent.dbgmodel.jna.dbgmodel.concept;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IPreferredRuntimeTypeConcept extends IUnknownEx {
	final IID IID_IPREFERRED_RUNTIME_TYPE_CONCEPT = new IID("9D6C1D7B-A76F-4618-8068-5F76BD9A4E8A");

	enum VTIndices implements VTableIndex {
		CAST_TO_PREFERRED_RUNTIME_TYPE, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT CastToPreferredRuntimeType(Pointer contextObject, PointerByReference object);

}
