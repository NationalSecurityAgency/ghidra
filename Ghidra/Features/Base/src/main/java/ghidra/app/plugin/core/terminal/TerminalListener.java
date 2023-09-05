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

/**
 * A listener for various events on a terminal panel
 */
public interface TerminalListener {
	/**
	 * The terminal was resized by the user
	 * 
	 * <p>
	 * If applicable and possible, this information should be communicated to the connection
	 * 
	 * @param cols the number of columns
	 * @param rows the number of rows
	 */
	default void resized(short cols, short rows) {
	}

	/**
	 * The application requested the window title changed
	 * 
	 * @param title the requested title
	 */
	default void retitled(String title) {
	}
}
