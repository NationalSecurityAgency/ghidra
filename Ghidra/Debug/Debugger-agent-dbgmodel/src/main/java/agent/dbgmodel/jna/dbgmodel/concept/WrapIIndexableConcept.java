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
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIIndexableConcept extends UnknownWithUtils implements IIndexableConcept {
	public static class ByReference extends WrapIIndexableConcept implements Structure.ByReference {
	}

	public WrapIIndexableConcept() {
	}

	public WrapIIndexableConcept(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetDimensionality(Pointer contextObject, ULONGLONGByReference dimensionality) {
		return _invokeHR(VTIndices.GET_DIMENSIONALITY, getPointer(), contextObject, dimensionality);
	}

	@Override
	public HRESULT GetAt(Pointer contextObject, ULONGLONG indexerCount, Pointer[] indexers,
			PointerByReference object, PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_AT, getPointer(), contextObject, indexerCount, indexers,
			object, metadata);
	}

	@Override
	public HRESULT SetAt(Pointer contextObject, ULONGLONG indexerCount, PointerByReference indexers,
			Pointer value) {
		return _invokeHR(VTIndices.SET_AT, getPointer(), contextObject, indexerCount, indexers,
			value);
	}

}
