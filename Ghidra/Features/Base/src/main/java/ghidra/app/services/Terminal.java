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
package ghidra.app.services;

import java.nio.ByteBuffer;

import ghidra.app.plugin.core.terminal.TerminalListener;

/**
 * A handle to a terminal window in the UI.
 */
public interface Terminal extends AutoCloseable {
	/**
	 * Add a listener for terminal events
	 * 
	 * @param listener the listener
	 */
	void addTerminalListener(TerminalListener listener);

	/**
	 * Remove a listener for terminal events
	 * 
	 * @param listener the listener
	 */
	void removeTerminalListener(TerminalListener listener);

	/**
	 * Process the given buffer as if it were output by the terminal's application.
	 * 
	 * <p>
	 * <b>Warning:</b> While implementations may synchronize to ensure the additional buffer is not
	 * processed at the same time as actual application input, there may not be any effort to ensure
	 * that the buffer is not injected in the middle of an escape sequence. Even if the injection is
	 * outside an escape sequence, this may still lead to unexpected behavior, since the injected
	 * output may be affected by or otherwise interfere with the application's control of the
	 * terminal's state. Generally, this should only be used for testing, or other cases when the
	 * caller knows it has exclusive control of the terminal.
	 * 
	 * @param bb the buffer of bytes to inject
	 */
	void injectDisplayOutput(ByteBuffer bb);

	/**
	 * @see #injectDisplayOutput(ByteBuffer)
	 */
	default void injectDisplayOutput(byte[] arr) {
		injectDisplayOutput(ByteBuffer.wrap(arr));
	}

	/**
	 * Set the terminal size to the given dimensions, as do <em>not</em> resize it to the window.
	 * 
	 * @param rows the number of rows
	 * @param cols the number of columns
	 */
	void setFixedSize(int rows, int cols);

	/**
	 * Fit the terminals dimensions to the containing window.
	 */
	void setDynamicSize();

	@Override
	void close();
}
