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
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIStringDisplayableConcept extends UnknownWithUtils
		implements IStringDisplayableConcept {
	public static class ByReference extends WrapIStringDisplayableConcept
			implements Structure.ByReference {
	}

	public WrapIStringDisplayableConcept() {
	}

	public WrapIStringDisplayableConcept(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT ToDisplayString(Pointer contextObject, Pointer metadata,
			BSTRByReference displayString) {
		return _invokeHR(VTIndices.TO_DISPLAY_STRING, getPointer(), contextObject, metadata,
			displayString);
	}

}
