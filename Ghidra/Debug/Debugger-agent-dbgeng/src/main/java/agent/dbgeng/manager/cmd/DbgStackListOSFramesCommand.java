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

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgStackFrame;
import agent.dbgeng.manager.evt.AbstractDbgCompletedCommandEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgStackFrameImpl;
import agent.dbgeng.manager.impl.DbgThreadImpl;

public class DbgStackListOSFramesCommand extends AbstractDbgCommand<List<DbgStackFrame>> {
	protected final DbgThreadImpl thread;
	private List<DbgStackFrame> result = new ArrayList<>();

	public DbgStackListOSFramesCommand(DbgManagerImpl manager, DbgThreadImpl thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public boolean handle(DbgEvent<?> evt, DbgPendingCommand<?> pending) {
		if (evt instanceof AbstractDbgCompletedCommandEvent && pending.getCommand().equals(this)) {
			return true;
		}
		else if (evt instanceof DbgConsoleOutputEvent) {
			pending.steal(evt);
		}
		return false;
	}

	@Override
	public List<DbgStackFrame> complete(DbgPendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (DbgConsoleOutputEvent out : pending.findAllOf(DbgConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		parse(builder.toString());
		return result;
	}

	private void parse(String output) {
		String[] lines = output.split("\n");
		int fcount = 0;
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (line.contains(" : ") && !line.startsWith("Child") && !line.startsWith("THREAD")) {
				String[] fields = line.trim().split("\\s+");
				DbgStackFrame frame = new DbgStackFrameImpl(thread, //
					fcount++, //
					parseToBig(fields[1]), // return
					fields.length > 8 ? fields[8] : ""
				); 
				result.add(frame);
			}		
		}		
	}
	
	private BigInteger parseToBig(String lval) {
		if (lval.contains("`")) {
			lval = lval.replaceAll("`", "");
		}
		return new BigInteger(lval, 16);
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		control.execute("!thread "+Long.toHexString(thread.getOffset())+" 6");		

	}
	
//	@Override
//	public void invoke() {
//		result = new ArrayList<>();
//		DebugSystemObjects so = manager.getSystemObjects();
//		DebugThreadId previous = so.getCurrentThreadId();
//		so.setCurrentThreadId(thread.getId());
//		DebugStackInformation stackTrace = manager.getControl().getStackTrace(0L, 0L, 0L);
//		for (int i = 0; i < stackTrace.getNumberOfFrames(); i++) {
//			DEBUG_STACK_FRAME tf = stackTrace.getFrame(i);
//			//DbgStackFrame frame = new DbgStackFrameImpl(thread, tf.FrameNumber.intValue(),
//			//	new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), null);
//			DbgStackFrame frame = new DbgStackFrameImpl(thread, //
//				tf.FrameNumber.intValue(), //
//				new BigInteger(Long.toHexString(tf.InstructionOffset.longValue()), 16), //
//				tf.FuncTableEntry.longValue(), //
//				tf.FrameOffset.longValue(), //
//				tf.ReturnOffset.longValue(), //
//				tf.StackOffset.longValue(), //
//				tf.Virtual.booleanValue(), //
//				tf.Params[0].longValue(), //
//				tf.Params[1].longValue(), //
//				tf.Params[2].longValue(), //
//				tf.Params[3].longValue());
//			result.add(frame);
//		}
//		so.setCurrentThreadId(previous);
//	}
}
