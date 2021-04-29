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
package agent.dbgeng.jna.dbgeng.sysobj;

import com.sun.jna.platform.win32.Guid.IID;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSystemObjects4 extends IDebugSystemObjects3 {
	final IID IID_IDEBUG_SYSTEM_OBJECTS4 = new IID("489468e6-7d0f-4af5-87ab-25207454d553");

	enum VTIndices4 implements VTableIndex {
		GET_CURRENT_PROCESS_EXECUTABLE_NAME_WIDE, //
		GET_CURRENT_SYSTEM_SERVER_NAME_WIDE, //
		;

		static int start = VTableIndex.follow(VTIndices3.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
