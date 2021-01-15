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
package agent.gdb.model;

import java.util.concurrent.CompletableFuture;

import org.junit.Ignore;

import agent.gdb.model.impl.GdbModelImpl;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.util.Msg;

@Ignore("Need compatible GDB version for CI")
public class ModelForGdbTest extends AbstractModelForGdbTest {

	static class GdbGadpModelHost implements ModelHost {
		final GdbModelImpl model;
		final String gdbCmd;

		GdbGadpModelHost(String gdbCmd) {
			model = new GdbModelImpl();
			this.gdbCmd = gdbCmd;
		}

		@Override
		public CompletableFuture<Void> init() {
			Msg.debug(this, "Starting GDB...");
			return model.startGDB(gdbCmd, new String[] {});
		}

		@Override
		public DebuggerObjectModel getModel() {
			return model;
		}

		@Override
		public void close() throws Exception {
			model.terminate();
		}
	}

	@Override
	protected ModelHost modelHost(String gdbCmd) throws Exception {
		return new GdbGadpModelHost(gdbCmd);
	}
}
