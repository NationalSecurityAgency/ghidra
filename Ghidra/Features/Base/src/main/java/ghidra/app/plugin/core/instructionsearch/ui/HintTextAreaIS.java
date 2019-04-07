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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.Color;
import java.awt.Font;

import docking.widgets.textarea.HintTextArea;

/**
 * Allows users to provide a text hint in a text field, shown only when the text is empty. 
 * 
 * Hint text will be shown in light grey, italicized, and in angle brackets.  Normal text will
 * be plain black.
 */
public class HintTextAreaIS extends HintTextArea {

	private String hint;

	/**
	 * Constructs the class with the hint text to be shown.
	 * 
	 * @param hint
	 */
	public HintTextAreaIS(final String hint) {
		super(hint);
	}

	/**
	 * Invoked. when the text in the box does not pass validation.
	 */
	public void setError() {
		setErrorAttributes();
	}

	/**
	 * Invoked when the text in the box passes validation.
	 */
	public void setValid() {
		setAttributes();
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Sets the text attributes to be used when there is an error in the input.
	 */
	private void setErrorAttributes() {
		this.setFont(getFont().deriveFont(Font.PLAIN));
		setForeground(Color.RED);
	}

}
