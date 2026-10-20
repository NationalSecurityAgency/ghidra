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
package utilities.util;

import java.util.Deque;
import java.util.LinkedList;
import java.util.stream.Collectors;

import ghidra.util.Msg;

public class DbgMsgTracer {
	private static final ThreadLocal<DbgMsgTracer> INSTANCES =
		ThreadLocal.withInitial(DbgMsgTracer::new);

	private final Deque<CallRec> stack = new LinkedList<>();

	public static CallRec rec(Object obj, String name) {
		DbgMsgTracer tracer = INSTANCES.get();
		CallRec rec = new CallRec(tracer, obj, name, System.currentTimeMillis());
		tracer.stack.push(rec);
		tracer.doMsg(obj, "%d: (ENTER)".formatted(rec.start));
		return rec;
	}

	String prefixStack() {
		return stack.reversed().stream().map(CallRec::name).collect(Collectors.joining(" > "));
	}

	public static void msg(Object obj, String message) {
		INSTANCES.get().doMsg(obj, message);
	}

	private void doMsg(Object obj, String message) {
		Msg.info(obj, "%s %s %s".formatted(Thread.currentThread(), prefixStack(), message));
	}

	public record CallRec(DbgMsgTracer tracer, Object obj, String name, long start)
			implements AutoCloseable {
		@Override
		public void close() {
			long stop = System.currentTimeMillis();
			long elapsedMs = stop - start;
			String extra;
			if (elapsedMs > 100) {
				extra = " (LONG)";
			}
			else {
				extra = "";
			}
			tracer.doMsg(obj,
				"%d: (EXITED) after %f s%s".formatted(stop, elapsedMs / 1000.0, extra));
			CallRec popped = tracer.stack.pop();
			assert popped == this;
		}
	}
}
