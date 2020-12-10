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
package agent.dbgmodel.jna.dbgmodel.datamodel.script;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelScript extends UnknownWithUtils implements IDataModelScript {
	public static class ByReference extends WrapIDataModelScript implements Structure.ByReference {
	}

	public WrapIDataModelScript() {
	}

	public WrapIDataModelScript(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetName(BSTRByReference scriptName) {
		return _invokeHR(VTIndices.GET_NAME, getPointer(), scriptName);
	}

	@Override
	public HRESULT Rename(WString scriptName) {
		return _invokeHR(VTIndices.RENAME, getPointer(), scriptName);
	}

	@Override
	public HRESULT Populate(Pointer contentStream) {
		return _invokeHR(VTIndices.POPULATE, getPointer(), contentStream);
	}

	@Override
	public HRESULT Execute(Pointer client) {
		return _invokeHR(VTIndices.EXECUTE, getPointer(), client);
	}

	@Override
	public HRESULT Unlink() {
		return _invokeHR(VTIndices.UNLINK, getPointer());
	}

	@Override
	public HRESULT IsInvocable(BOOLByReference isInvocable) {
		return _invokeHR(VTIndices.IS_INVOCABLE, getPointer(), isInvocable);
	}

	@Override
	public HRESULT InvokeMain(Pointer client) {
		return _invokeHR(VTIndices.INVOKE_MAIN, getPointer(), client);
	}

}
