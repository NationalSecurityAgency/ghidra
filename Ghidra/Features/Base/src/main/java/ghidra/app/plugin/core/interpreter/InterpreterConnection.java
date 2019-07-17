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
package ghidra.app.plugin.core.interpreter;

import java.util.List;

import javax.swing.ImageIcon;

import ghidra.app.plugin.core.console.CodeCompletion;

/**
 * A connection between an implementation of an interpreter and its generic GUI components.
 */
public interface InterpreterConnection {

	/**
	 * Gets the title of the interpreter.
	 * 
	 * @return The title of the interpreter
	 */
	public String getTitle();

	/**
	 * Gets the icon associated with the interpreter.
	 * 
	 * @return The icon associated with the interpreter.  Null if default icon is desired.
	 */
	public ImageIcon getIcon();

	/**
	 * Gets a {@link List} of {@link CodeCompletion code completions} for the given command.
	 * 
	 * @param cmd The command to get code completions for
	 * @return A {@link List} of {@link CodeCompletion code completions} for the given command
	 */
	public List<CodeCompletion> getCompletions(String cmd);
}
