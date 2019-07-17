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
package ghidra.app.plugin.assembler.sleigh;

import org.junit.Test;

import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.DbgCtx;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer.TabbingOutputStream;

public class DbgTimerTest {
	@Test
	public void testDbgTimer() {
		try (DbgTimer dbg = new DbgTimer()) {
			dbg.println("The first line");
			try (DbgCtx dc = dbg.start("First push")) {
				dbg.println("An indented line");
			}
			dbg.println("The last line");
			TabbingOutputStream old = dbg.setOutputStream(System.err);
			dbg.println("The error line");
			try (DbgCtx dc = dbg.start("Error push")) {
				dbg.println("An indented error line");
			}
			dbg.println("The last error line");
			dbg.resetOutputStream(old);
		}
	}
}
