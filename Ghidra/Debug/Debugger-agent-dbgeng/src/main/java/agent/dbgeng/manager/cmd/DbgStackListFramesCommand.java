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
package agent.dbgeng.manager.cmd;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;
import agent.dbgeng.manager.DbgStackFrame;
import agent.dbgeng.manager.impl.*;

public class DbgStackListFramesCommand extends AbstractDbgCommand<List<DbgStackFrame>> {
	protected final DbgThreadImpl thread;
	private List<DbgStackFrame> result;

	public DbgStackListFramesCommand(DbgManagerImpl manager, DbgThreadImpl thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public List<DbgStackFrame> complete(DbgPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new ArrayList<>();
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId previous = so.getCurrentThreadId();
		so.setCurrentThreadId(thread.getId());
		DebugStackInformation stackTrace = manager.getControl().getStackTrace(0L, 0L, 0L);
		for (int i = 0; i < stackTrace.getNumberOfFrames(); i++) {
			DEBUG_STACK_FRAME tf = stackTrace.getFrame(i);
			//DbgStackFrame frame = new DbgStackFrameImpl(thread, tf.FrameNumber.intValue(),
			//	new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), null);
			DbgStackFrame frame = new DbgStackFrameImpl(thread, //
				tf.FrameNumber.intValue(), //
				new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), //
				tf.FuncTableEntry.longValue(), //
				tf.FrameOffset.longValue(), //
				tf.ReturnOffset.longValue(), //
				tf.StackOffset.longValue(), //
				tf.Virtual.booleanValue(), //
				tf.Params[0].longValue(), //
				tf.Params[1].longValue(), //
				tf.Params[2].longValue(), //
				tf.Params[3].longValue());
			result.add(frame);
		}
		so.setCurrentThreadId(previous);
	}
}
