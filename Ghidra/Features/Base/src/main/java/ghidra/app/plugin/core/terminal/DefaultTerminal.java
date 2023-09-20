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
	public void terminated() {
		provider.terminated();
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
	public void setSubTitle(String title) {
		Swing.runIfSwingOrRunLater(() -> provider.setSubTitle(title));
	}

	@Override
	public String getSubTitle() {
		return provider.getSubTitle();
	}

	@Override
	public void setFixedSize(short cols, short rows) {
		provider.setFixedSize(cols, rows);
	}

	@Override
	public void setDynamicSize() {
		provider.setDyanmicSize();
	}

	@Override
	public int getColumns() {
		return provider.getColumns();
	}

	@Override
	public int getRows() {
		return provider.getRows();
	}

	@Override
	public void setMaxScrollBackRows(int rows) {
		provider.setMaxScrollBackRows(rows);
	}

	@Override
	public int getScrollBackRows() {
		return provider.getScrollBackRows();
	}

	@Override
	public String getDisplayText() {
		return getRangeText(0, 0, getColumns(), getRows());
	}

	@Override
	public String getFullText() {
		return getRangeText(0, -getScrollBackRows(), getColumns(), getRows());
	}

	@Override
	public String getLineText(int line) {
		return getRangeText(0, line, getColumns(), line);
	}

	@Override
	public String getRangeText(int startCol, int startLine, int endCol, int endLine) {
		return provider.getRangeText(startCol, startLine, endCol, endLine);
	}

	@Override
	public int getCursorColumn() {
		return provider.getCursorColumn();
	}

	@Override
	public int getCursorRow() {
		return provider.getCursorRow();
	}

	@Override
	public void setTerminateAction(Runnable action) {
		Swing.runIfSwingOrRunLater(() -> provider.setTerminateAction(action));
	}
}
