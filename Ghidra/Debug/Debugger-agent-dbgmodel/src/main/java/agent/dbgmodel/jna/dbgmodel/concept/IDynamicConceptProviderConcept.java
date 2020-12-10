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
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDynamicConceptProviderConcept extends IUnknownEx {
	final IID IID_IDYNAMIC_CONCEPT_PROVIDER_CONCEPT =
		new IID("95A7F7DD-602E-483f-9D06-A15C0EE13174");

	enum VTIndices implements VTableIndex {
		GET_CONCEPT, //
		SET_CONCEPT, //
		NOTIFY_PARENT, //
		NOTIFY_PARENT_CHANGE, //
		NOTIFY_DESTRUCT, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetConcept(Pointer contextObject, REFIID conceptId, PointerByReference conceptInterface,
			PointerByReference conceptMetadata, BOOLByReference hasConcept);

	HRESULT SetConcept(Pointer contextObject, REFIID conceptId, Pointer conceptInterface,
			Pointer conceptMetadata);

	HRESULT NotifyParent(Pointer parentModel);

	HRESULT NotifyParentChange(Pointer parentModel);

	HRESULT NotifyDestruct();

}
