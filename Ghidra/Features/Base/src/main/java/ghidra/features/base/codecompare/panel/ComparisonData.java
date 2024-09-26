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
package ghidra.features.base.codecompare.panel;

import java.awt.Color;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * ComparisonData is an abstract of items that can be compared in a {@link CodeComparisonPanel}. 
 * Not all comparison panels can handle all types of comparison data. For example, the decompiler
 * comparison only works when the comparison data is a function.
 */
public interface ComparisonData {
	public static final Color FG_COLOR_TITLE = Palette.DARK_GRAY;
	public static final ComparisonData EMPTY = new EmptyComparisonData();

	/**
	 * Returns the function being compared or null if this comparison data is not function based.
	 * @return the function being compared or null if this comparison data is not function based
	 */
	public Function getFunction();

	/**
	 * Returns the set of addresses being compared. Currently, all comparisons are address based,
	 * so this should never be null.
	 * @return the set of addresses being compared
	 */
	public AddressSetView getAddressSet();

	/**
	 * Returns the program containing the data being compared. 
	 * @return the program containing the data being compared.
	 */
	public Program getProgram();

	/**
	 * Returns a description of the data being compared.
	 * @return a description of the data being compared.
	 */
	public String getDescription();

	/** 
	 * Returns a short description (useful for tab name)
	 * @return a short description
	 */
	public String getShortDescription();

	/**
	 * Returns true if this comparison has no addresses to compare
	 * @return true if this comparison has no addresses to compare
	 */
	public boolean isEmpty();

}
