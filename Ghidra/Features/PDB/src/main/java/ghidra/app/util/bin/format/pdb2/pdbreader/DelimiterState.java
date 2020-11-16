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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * This is a utility class, containing state, used for providing delimiters in a sequence
 *  of outputs. 
 */
public class DelimiterState {

	private String delimStart;
	private String delim;
	private boolean first;

	/**
	 * Constructor. 
	 * @param delimStart {@link String} output to be provided before the first item in a list, only
	 *  when at least one item is found in the list.
	 * @param delim Delimiter char(s) to be output prior to any outputs subsequent to a first
	 *  output.
	 */
	public DelimiterState(String delimStart, String delim) {
		this.delimStart = delimStart;
		this.delim = delim;
		first = true;
	}

	public void reset() {
		first = true;
	}

	/**
	 * Method that adds delimiter information (based on the state to the {@link String}
	 *  representation of the input object.  The boolean argument is available to give the
	 *  caller a single-line way of calling the method in a conditional sense (i.e., eliminates
	 *  the need for a conditional block wrapping the call).
	 * @param output True: act as though called; false: act as though call was not made.
	 * @param obj {@link Object} to be output.
	 * @return {@link String} result that contains the {@link AbstractParsableItem} and any
	 *  delimiter output based on the state.
	 */
	public String out(boolean output, Object obj) {
		return out(output, String.valueOf(obj));
	}

	/**
	 * Method that adds delimiter information (based on the state to the {@link String}
	 *  representation of the input argument.  The boolean argument is available to give the
	 *  caller a single-line way of calling the method in a conditional sense (i.e., eliminates
	 *  the need for a conditional block wrapping the call).
	 * @param output True: act as though called; false: act as though call was not made.
	 * @param item {@link AbstractParsableItem} to be output.
	 * @return {@link String} result that contains the {@link AbstractParsableItem} and any
	 *  delimiter output based on the state.
	 */
	public String out(boolean output, AbstractParsableItem item) {
		return out(output, item.toString());
	}

	/**
	 * Method that adds delimiter information (based on the state to the {@link String}
	 *  representation of the input argument.  The boolean argument is available to give the
	 *  caller a single-line way of calling the method in a conditional sense (i.e., eliminates
	 *  the need for a conditional block wrapping the call).
	 * @param output True: act as though called; false: act as though call was not made.
	 * @param val {@link String} to be output.
	 * @return {@link String} result that contains the {@link String} argument and any delimiter
	 *  output based on the state.
	 */
	public String out(boolean output, String val) {
		if (output) {
			if (first) {
				first = false;
				return delimStart + val;
			}
			return delim + val;
		}
		return "";
	}

}
