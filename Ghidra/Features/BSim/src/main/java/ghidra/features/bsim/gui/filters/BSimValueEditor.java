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
package ghidra.features.bsim.gui.filters;

import java.awt.Color;
import java.util.List;

import javax.swing.JComponent;

import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Palette;

/**
 * Interface for BSim filter value editors. Some BSim editors can support multiple values, so the 
 * getValues, setValues methods all work on lists of strings.
 */
public interface BSimValueEditor {
	public static final String FILTER_DELIMETER = ",";
	public static final Color VALID_COLOR = Colors.BACKGROUND;
	public static final Color INVALID_COLOR = Palette.getColor("mistyrose");

	/**
	 * Sets the editor to the given string values. They are displayed in the GUI as comma separated
	 * values.
	 * @param values the values to be used as the current editor values
	 */
	public void setValues(List<String> values);

	/**
	 * Returns the current set of editor values.
	 * @return the current set of editor values
	 */
	public List<String> getValues();

	/**
	 * returns the GUI component used to allow the user to see and change editor values.
	 * @return the GUI component used to allow the user to see and change editor values
	 */
	public JComponent getComponent();

	/**
	 * Returns true if the editor has valid values as determined by the editor's corresponding 
	 * {@link BSimFilterType#isValidValue}.
	 * @return true if the editor has valid values as determined by the editor's corresponding 
	 * filter type.
	 */
	public boolean hasValidValues();

}
