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
package agent.dbgeng.manager.evt;

import agent.dbgeng.dbgeng.DebugClient.ChangeEngineState;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgStackFrameImpl;
import ghidra.comm.util.BitmaskSet;

public class DbgStateChangedEvent extends AbstractDbgEvent<BitmaskSet<ChangeEngineState>> {

	private long argument;
	private DbgState state = null;

	public DbgStateChangedEvent(BitmaskSet<ChangeEngineState> flags) {
		super(flags);
	}

	public long getArgument() {
		return argument;
	}

	public void setArgument(long argument) {
		this.argument = argument;
	}

	public DbgStackFrameImpl getFrame(DbgThread thread) {
		return null;
	}

	@Override
	public DbgState newState() {
		return state;
	}

	public void setState(DbgState state) {
		this.state = state;
	}
}
