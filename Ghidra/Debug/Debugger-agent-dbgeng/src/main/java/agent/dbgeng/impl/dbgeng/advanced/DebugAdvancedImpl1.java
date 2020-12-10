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
package agent.dbgeng.impl.dbgeng.advanced;

import agent.dbgeng.dbgeng.DbgEng;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.jna.dbgeng.advanced.IDebugAdvanced;

public class DebugAdvancedImpl1 implements DebugAdvancedInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	@SuppressWarnings("unused")
	private final IDebugAdvanced jnaAdvanced;

	public DebugAdvancedImpl1(IDebugAdvanced jnaAdvanced) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaAdvanced);
		this.jnaAdvanced = jnaAdvanced;
	}

	@Override
	public DebugThreadBasicInformation getThreadBasicInformation(DebugThreadId tid) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}
}
