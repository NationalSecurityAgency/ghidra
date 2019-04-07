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
package ghidra.app.merge.listing;

/**
 * <code>UserDefinedPropertyPanel</code> adds a checkbox as the southern component
 * of the <code>VerticalChoicesPanel</code>. The check box allows the user to 
 * indicate that they want to select the same option for all conflicts of a 
 * particular property type.
 */
class UserDefinedPropertyPanel extends VerticalChoicesPanel {

	private final static long serialVersionUID = 1;

	/**
	 * Creates a panel for displaying and resolving User Defined Property conflicts.
	 */
	UserDefinedPropertyPanel() {
		super();
	}

	/**
	 * Creates a panel for displaying and resolving User Defined Property conflicts.
	 * @param isDoubleBuffered
	 */
	UserDefinedPropertyPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
	}
}
