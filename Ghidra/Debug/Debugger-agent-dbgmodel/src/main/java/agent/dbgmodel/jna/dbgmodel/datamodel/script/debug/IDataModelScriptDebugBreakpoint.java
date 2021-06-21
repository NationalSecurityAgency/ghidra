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
package agent.dbgmodel.jna.dbgmodel.datamodel.script.debug;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelScriptDebugBreakpoint extends IUnknownEx {
	final IID IID_IDATA_MODEL_SCRIPT_DEBUG_BREAKPOINT =
		new IID("6BB27B35-02E6-47cb-90A0-5371244032DE");

	enum VTIndices implements VTableIndex {
		GET_ID, //
		IS_ENABLED, //
		ENABLE, //
		DISABLE, //
		REMOVE, //
		GET_POSITION, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetId();

	HRESULT IsEnabled();

	HRESULT Enable();

	HRESULT Disable();

	HRESULT Remove();

	HRESULT GetPosition(Pointer position, Pointer positionSpanEnd, WString lineText);

}
