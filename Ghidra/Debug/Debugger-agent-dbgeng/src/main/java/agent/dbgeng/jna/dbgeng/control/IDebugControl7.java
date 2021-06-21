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
package agent.dbgeng.jna.dbgeng.control;

import com.sun.jna.platform.win32.Guid.IID;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugControl7 extends IDebugControl6 {
	final IID IID_IDEBUG_CONTROL7 = new IID("b86fb3b1-80d4-475b-aea3-cf06539cf63a");

	enum VTIndices7 implements VTableIndex {
		GET_DEBUGGEE_TYPE2, //
		;

		static int start = VTableIndex.follow(VTIndices6.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
