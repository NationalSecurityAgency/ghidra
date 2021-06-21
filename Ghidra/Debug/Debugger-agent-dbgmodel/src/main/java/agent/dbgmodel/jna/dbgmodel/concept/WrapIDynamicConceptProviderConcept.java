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
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDynamicConceptProviderConcept extends UnknownWithUtils
		implements IDynamicConceptProviderConcept {
	public static class ByReference extends WrapIDynamicConceptProviderConcept
			implements Structure.ByReference {
	}

	public WrapIDynamicConceptProviderConcept() {
	}

	public WrapIDynamicConceptProviderConcept(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetConcept(Pointer contextObject, REFIID conceptId,
			PointerByReference conceptInterface,
			PointerByReference conceptMetadata, BOOLByReference hasConcept) {
		return _invokeHR(VTIndices.GET_CONCEPT, getPointer(), contextObject, conceptId,
			conceptInterface, conceptMetadata, hasConcept);
	}

	@Override
	public HRESULT SetConcept(Pointer contextObject, REFIID conceptId, Pointer conceptInterface,
			Pointer conceptMetadata) {
		return _invokeHR(VTIndices.SET_CONCEPT, getPointer(), contextObject, conceptId,
			conceptInterface, conceptMetadata);
	}

	@Override
	public HRESULT NotifyParent(Pointer parentModel) {
		return _invokeHR(VTIndices.NOTIFY_PARENT, getPointer(), parentModel);
	}

	@Override
	public HRESULT NotifyParentChange(Pointer parentModel) {
		return _invokeHR(VTIndices.NOTIFY_PARENT_CHANGE, getPointer(), parentModel);
	}

	@Override
	public HRESULT NotifyDestruct() {
		return _invokeHR(VTIndices.NOTIFY_DESTRUCT, getPointer());
	}

}
