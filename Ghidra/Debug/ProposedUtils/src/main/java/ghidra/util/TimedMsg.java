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
package ghidra.util;

import java.util.function.BiConsumer;

public class TimedMsg {
	private static long last = 0;

	private synchronized static void doMsg(BiConsumer<Object, String> msg, Object originator,
			String message) {
		if (last == 0) {
			last = System.currentTimeMillis();
			msg.accept(originator, "(started) " + message);
		}
		else {
			long now = System.currentTimeMillis();
			long lapsed = now - last;
			last = now;
			msg.accept(originator, "(" + lapsed + " ms) " + message);
		}
	}

	public static void debug(Object originator, String message) {
		doMsg(Msg::debug, originator, message);
	}
}
