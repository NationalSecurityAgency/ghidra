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

public interface IDebugControl3 extends IDebugControl2 {
	final IID IID_IDEBUG_CONTROL3 = new IID("7df74a86-b03f-407f-90ab-a20dadcead08");

	enum VTIndices3 implements VTableIndex {
		GET_ASSEMBLY_OPTIONS, //
		ADD_ASSEMBLY_OPTIONS, //
		REMOVE_ASSEMBLY_OPTIONS, //
		SET_ASSEMBLY_OPTIONS, //
		GET_EXPRESSION_SYNTAX, //
		SET_EXPRESSION_SYNTAX, //
		SET_EXPRESSION_SYNTAX_BY_NAME, //
		GET_NUMBER_EXPRESSION_SYNTAXES, //
		GET_EXPRESSION_SYNTAX_NAMES, //
		GET_NUMBER_EVENTS, //
		GET_EVENT_INDEX_DESCRIPTION, //
		GET_CURRENT_EVENT_INDEX, //
		SET_NEXT_EVENT_INDEX, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
