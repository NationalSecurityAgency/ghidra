/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
 * - a description of the completion (what are you completing?)
 * - the actual String that will be inserted
 * - an optional Component that will be in the completion List
 * 
 * 
 *
 */
public class CodeCompletion implements Comparable<CodeCompletion> {
	private String description;
	private String insertion;
	private JComponent component;

	
	/**
	 * Returns true if the given CodeCompletion actually would insert something.
	 * 
	 * @param completion a CodeCompletion
	 */
	public static boolean isValid(CodeCompletion completion) {
		return ((completion != null) &&
				(completion.getInsertion() != null));
	}

	
	/**
	 * Construct a new CodeCompletion.
	 * 
	 * @param description description of this completion
	 * @param insertion what will be inserted (or null)
	 * @param comp (optional) Component to appear in completion List (or null)
	 */
	public CodeCompletion(String description, String insertion,
			JComponent comp) {
		this.description = description;
		this.insertion = insertion;
		this.component = comp;
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
