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
package docking.options.editor;

import java.awt.Dimension;
import java.beans.PropertyEditor;

/**
 * A simple interface for options {@link PropertyEditor}s to signal that they provide a custom 
 * option editor that would like to be aligned with other options in the same view.
 */
public interface OptionsEditorAlignable {

	/**
	 * {@return Gets the preferred alignment size of this class.}
	 */
	public Dimension getPreferredAlignmentSize();

	/**
	 * Sets the final preferred alignment size after merging all preferred sizes from all options
	 * components in the view.
	 * @param size the size
	 */
	public void setPreferredAlignmentSize(Dimension size);
}
