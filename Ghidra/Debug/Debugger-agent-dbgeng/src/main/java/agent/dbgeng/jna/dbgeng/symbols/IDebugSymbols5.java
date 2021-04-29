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
package agent.dbgeng.jna.dbgeng.symbols;

import com.sun.jna.platform.win32.Guid.IID;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSymbols5 extends IDebugSymbols4 {
	final IID IID_IDEBUG_SYMBOLS5 = new IID("c65fa83e-1e69-475e-8e0e-b5d79e9cc17e");

	enum VTIndices5 implements VTableIndex {
		GET_CURRENT_SCOPE_FRAME_INDEX_EX, //
		SET_SCOPE_FRAME_BY_INDEX_EX, //
		;

		static int start = VTableIndex.follow(VTIndices4.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
