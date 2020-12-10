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

public interface IDebugDataSpaces3 extends IDebugDataSpaces2 {
	final IID IID_IDEBUG_DATA_SPACES3 = new IID("23f79d6c-8aaf-4f7c-a607-9995f5407e63");

	enum VTIndices3 implements VTableIndex {
		READ_IMAGE_NT_HEADERS, //
		READ_TAGGED, //
		START_ENUM_TAGGED, //
		GET_NEXT_TAGGED, //
		END_ENUM_TAGGED, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
