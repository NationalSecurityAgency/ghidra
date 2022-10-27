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
package ghidra.app.plugin.core.console;

import javax.swing.JComponent;

/**
 * This class encapsulates a code completion.
 * 
 * It is intended to be used by the code completion process, especially the
 * CodeCompletionWindow.  It encapsulates:
 * <ul>
 * <li> a description of the completion (what are you completing?)
 * <li> the actual String that will be inserted
 * <li> an optional Component that will be in the completion List
 * <li> the number of characters to remove before the insertion of the completion
 * </ul>
 * <p>
 * For example, if one wants to autocomplete a string "Runscr" into "runScript", 
 * the fields may look as follows:
 * <ul>
 * <li> description: "runScript (Method)"
 * <li> insertion: "runScript"
 * <li> component: null or JLabel("runScript (Method)")
 * <li> charsToRemove: 6 (i.e. the length of "Runscr", 
 *      as it may be required later to correctly replace the string)
 * </ul>
 */
public class CodeCompletion implements Comparable<CodeCompletion> {
	private String description;
	private String insertion;
	private JComponent component;
	private int charsToRemove;

	/**
	 * Returns true if the given CodeCompletion actually would insert something.
	 * 
	 * @param completion a CodeCompletion
	 * @return true if the given CodeCompletion actually would insert something
	 */
	public static boolean isValid(CodeCompletion completion) {
		return completion != null && completion.getInsertion() != null;
	}

	/**
	 * Construct a new CodeCompletion.
	 * 
	 * @param description description of this completion
	 * @param insertion what will be inserted (or null)
	 * @param comp (optional) Component to appear in completion List (or null)
	 */
	public CodeCompletion(String description, String insertion, JComponent comp) {
		this.description = description;
		this.insertion = insertion;
		this.component = comp;
		this.charsToRemove = 0;
	}

	/**
	 * Construct a new CodeCompletion.
	 * 
	 * @param description description of this completion
	 * @param insertion what will be inserted (or null)
	 * @param comp (optional) Component to appear in completion List (or null)
	 * @param charsToRemove the number of characters that should be removed before the insertion
	 */
	public CodeCompletion(String description, String insertion, JComponent comp,
			int charsToRemove) {
		this.description = description;
		this.insertion = insertion;
		this.component = comp;
		this.charsToRemove = charsToRemove;
	}

	/**
	 * Returns the Component to display in the completion list
	 * 
	 * @return the Component to display in the completion list
	 */
	public JComponent getComponent() {
		return component;
	}

	/**
	 * Returns the description of this CodeCompletion.
	 * 
	 * Typically this is what you are trying to complete.
	 * 
	 * @return the description of this CodeCompletion
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns the text to insert to complete the code.
	 * 
	 * @return the text to insert to complete the code
	 */
	public String getInsertion() {
		return insertion;
	}

	/**
	 * Returns the number of characters to remove from the input before the insertion
	 * of the code completion
	 * 
	 * @return the number of characters to remove
	 */
	public int getCharsToRemove() {
		return charsToRemove;
	}

	/**
	 * Returns a String representation of this CodeCompletion.
	 * 
	 * @return a String representation of this CodeCompletion
	 */
	@Override
	public String toString() {
		return "CodeCompletion: '" + getDescription() + "' (" + getInsertion() + ")";
	}

	public int compareTo(CodeCompletion that) {
		return this.description.compareToIgnoreCase(that.description);
	}
}
