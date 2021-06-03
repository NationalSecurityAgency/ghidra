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

public interface IDebugSystemObjects2 extends IDebugSystemObjects {
	final IID IID_IDEBUG_SYSTEM_OBJECTS2 = new IID("0ae9f5ff-1852-4679-b055-494bee6407ee");

	enum VTIndices2 implements VTableIndex {
		GET_CURRENT_PROCESS_UP_TIME, //
		GET_IMPLICIT_THREAD_DATA_OFFSET, //
		SET_IMPLICIT_THREAD_DATA_OFFSET, //
		GET_IMPLICIT_PROCESS_DATA_OFFSET, //
		SET_IMPLICIT_PROCESS_DATA_OFFSET, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
