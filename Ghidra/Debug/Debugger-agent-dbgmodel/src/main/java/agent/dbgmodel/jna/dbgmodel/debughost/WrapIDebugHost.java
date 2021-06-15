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
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHost extends UnknownWithUtils implements IDebugHost {
	public static class ByReference extends WrapIDebugHost implements Structure.ByReference {
	}

	public WrapIDebugHost() {
	}

	public WrapIDebugHost(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetHostDefinedInterface(PointerByReference hostUnk) {
		return _invokeHR(VTIndices.GET_HOST_DEFINED_INTERFACE, getPointer(), hostUnk);
	}

	@Override
	public HRESULT GetCurrentContext(PointerByReference context) {
		return _invokeHR(VTIndices.GET_CURRENT_CONTEXT, getPointer(), context);
	}

	@Override
	public HRESULT GetDefaultMetadata(PointerByReference defaultMetadataStore) {
		return _invokeHR(VTIndices.GET_DEFAULT_METADATA, getPointer(), defaultMetadataStore);
	}

}
