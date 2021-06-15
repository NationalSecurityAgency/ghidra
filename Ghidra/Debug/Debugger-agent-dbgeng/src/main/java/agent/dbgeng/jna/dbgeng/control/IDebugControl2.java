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

public interface IDebugControl2 extends IDebugControl {
	final IID IID_IDEBUG_CONTROL2 = new IID("d4366723-44df-4bed-8c7e-4c05424f4588");

	enum VTIndices2 implements VTableIndex {
		GET_CURRENT_TIME_DATE, //
		GET_CURRENT_SYSTEM_UP_TIME, //
		GET_DUMP_FORMAT_FLAGS, //
		GET_NUMBER_TEXT_REPLACEMENTS, //
		GET_TEXT_REPLACEMENT, //
		SET_TEXT_REPLACEMENT, //
		REMOVE_TEXT_REPLACEMENTS, //
		OUTPUT_TEXT_REPLACEMENTS, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
