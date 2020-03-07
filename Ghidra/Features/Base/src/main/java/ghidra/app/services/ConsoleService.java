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

import ghidra.app.plugin.core.console.ConsolePlugin;
import ghidra.framework.plugintool.ServiceInfo;

import java.io.PrintWriter;

/**
 * Generic console interface allowing any plugin to print
 * messages to console window.
 */
@ServiceInfo(defaultProvider = ConsolePlugin.class)
public interface ConsoleService {

	/**
	 * Appends message to the console text area.
	 * 
	 * For example:
	 *    "originator&gt; message"
	 * 
	 * @param originator  a descriptive name of the message creator
	 * @param message     the message to appear in the console
	 */
	public void addMessage(String originator, String message);

	/**
	 * Appends an error message to the console text area.
	 * The message should be rendered is such a way as to denote
	 * that it is an error. For example, display in "red".
	 * @param originator  a descriptive name of the message creator
	 * @param message     the message to appear in the console
	 */
	public void addErrorMessage(String originator, String message);

	/**
	 * Appends an exception to the console text area.
	 * @param originator  a descriptive name of the message creator
	 * @param exc         the exception 
	 */
	public void addException(String originator, Exception exc);

	/**
	 * Clears all messages from the console.
	 */
	public void clearMessages();

	/**
	 * Prints the message into the console.
	 * @param msg the messages to print into the console
	 */
	public void print(String msg);

	/**
	 * Prints the messages into the console followed by a line feed.
	 * @param msg the message to print into the console
	 */
	public void println(String msg);

	/**
	 * Prints the error message into the console.
	 * It will be displayed in red.
	 * @param errmsg the error message to print into the console
	 */
	public void printError(String errmsg);

	/**
	 * Prints the error message into the console followed by a line feed.
	 * It will be displayed in red.
	 * @param errmsg the error message to print into the console
	 */
	public void printlnError(String errmsg);

	/**
	 * Returns a print writer object to use as standard output.
	 * @return a print writer object to use as standard output
	 */
	public PrintWriter getStdOut();

	/**
	 * Returns a print writer object to use as standard error.
	 * @return a print writer object to use as standard error
	 */
	public PrintWriter getStdErr();

	/**
	 * Returns number of characters of currently 
	 * in the console.
	 * If the console is cleared, this number is reset.
	 * 
	 * Please note:
	 * Support for this method is optional
	 * based on the underlying console
	 * implementation. If this method cannot be supported,
	 * please throw {@link UnsupportedOperationException}.
	 * 
	 * @return number of characters &gt;= 0
	 * 
	 * @throws UnsupportedOperationException
	 */
	public int getTextLength();

	/**
	 * Fetches the text contained within the given portion 
	 * of the console.
	 * 
	 * Please note:
	 * Support for this method is optional
	 * based on the underlying console
	 * implementation. If this method cannot be supported,
	 * please throw {@link UnsupportedOperationException}.
	 * 
	 * @param offset  the offset into the console representing the desired start of the text &gt;= 0
	 * @param length  the length of the desired string &gt;= 0
	 * 
	 * @return the text, in a String of length &gt;= 0
	 * 
	 * @throws UnsupportedOperationException
	 */
	public String getText(int offset, int length);
}
