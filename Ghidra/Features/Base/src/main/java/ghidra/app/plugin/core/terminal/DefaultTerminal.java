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
package ghidra.app.plugin.core.terminal;

import java.nio.ByteBuffer;

import ghidra.app.plugin.core.terminal.vt.VtOutput;
import ghidra.app.services.Terminal;
import ghidra.util.Swing;

/**
 * A terminal that does nothing on its own.
 * 
 * <p>
 * Everything displayed happens via {@link #injectDisplayOutput(ByteBuffer)}, and everything typed
 * into it is emitted via the {@link VtOutput}, which was given at construction.
 */
public class DefaultTerminal implements Terminal {
	protected final TerminalProvider provider;

	public DefaultTerminal(TerminalProvider provider) {
		this.provider = provider;
	}

	@Override
	public void close() {
		Swing.runIfSwingOrRunLater(() -> provider.removeFromTool());
	}

	@Override
	public void addTerminalListener(TerminalListener listener) {
		provider.addTerminalListener(listener);
	}

	@Override
	public void removeTerminalListener(TerminalListener listener) {
		provider.removeTerminalListener(listener);
	}

	@Override
	public void injectDisplayOutput(ByteBuffer bb) {
		provider.processInput(bb);
	}

	@Override
	public void setFixedSize(int rows, int cols) {
		provider.setFixedSize(rows, cols);
	}

	@Override
	public void setDynamicSize() {
		provider.setDyanmicSize();
	}
}
