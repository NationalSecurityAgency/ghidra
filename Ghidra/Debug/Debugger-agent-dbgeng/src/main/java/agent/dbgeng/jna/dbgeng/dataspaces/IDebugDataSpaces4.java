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
package agent.dbgeng.jna.dbgeng.dataspaces;

import com.sun.jna.platform.win32.Guid.IID;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugDataSpaces4 extends IDebugDataSpaces3 {
	final IID IID_IDEBUG_DATA_SPACES4 = new IID("d98ada1f-29e9-4ef5-a6c0-e53349883212");

	enum VTIndices4 implements VTableIndex {
		GET_OFFSET_INFORMATION, //
		GET_NEXT_DIFFERENTLY_VALID_OFFSET_VIRTUAL, //
		GET_VALID_REGION_VIRTUAL, //
		SEARCH_VIRTUAL2, //
		READ_MULTI_BYTE_STRING_VIRTUAL, //
		READ_MULTI_BYTE_STRING_VIRTUAL_WIDE, //
		READ_UNICODE_STRING_VIRTUAL, //
		READ_UNICODE_STRING_VIRTUAL_WIDE, //
		READ_PHYSICAL2, //
		WRITE_PHYSICAL2, //
		;

		static int start = VTableIndex.follow(VTIndices3.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
