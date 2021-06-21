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

public interface IDebugControl5 extends IDebugControl4 {
	final IID IID_IDEBUG_CONTROL5 = new IID("b2ffe162-2412-429f-8d1d-5bf6dd824696");

	enum VTIndices5 implements VTableIndex {
		GET_STACK_TRACE_EX, //
		OUTPUT_STACK_TRACE_EX, //
		GET_CONTEXT_STACK_TRACE_EX, //
		OUTPUT_CONTEXT_STACK_TRACE_EX, //
		GET_BREAKPOINT_BY_GUID, //
		;

		static int start = VTableIndex.follow(VTIndices4.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
