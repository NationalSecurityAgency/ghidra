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
package agent.dbgeng.model;

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.impl.DbgModelImpl;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.util.Msg;

public class ModelForDbgTest extends AbstractModelForDbgTest {

	static class DbgGadpModelHost implements ModelHost {
		final DbgModelImpl model;

		DbgGadpModelHost() {
			model = new DbgModelImpl();
		}

		@Override
		public CompletableFuture<Void> init() {
			Msg.debug(this, "Starting dbgeng...");
			return model.startDbgEng(new String[] {});
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
	protected ModelHost modelHost() throws Exception {
		return new DbgGadpModelHost();
	}
}
