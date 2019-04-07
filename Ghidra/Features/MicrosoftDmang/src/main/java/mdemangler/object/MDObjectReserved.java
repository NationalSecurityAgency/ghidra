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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;

/**
 * This class represents MSFT Reserved Symbols as a base class for those that we are trying
 *  to parse.  If just this base class is assigned, then we plan to allow a fall-through for
 *  other processing outside of the demangler.
 */
public class MDObjectReserved extends MDObject {

	public MDObjectReserved(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
	}

	@Override
	protected void parseInternal() throws MDException {
		//Go to end of string.
		dmang.increment(dmang.getMangledSymbol().length() - dmang.getIndex());
	}

	/**
	 * This method returns the <b><code>String</code></b> containing the sequence of ASCII-represented digits
	 *  '0'-'9'.  The processing and capture of these digits is stopped when a non-digit
	 *  is encountered.
	 * @param dmang The <b><code>MDMang</code></b> demangler control.
	 * @return The <b><code>String</code></b> containing the digits.
	 */
	protected static String parseDigits(MDMang dmang) {
		String ret = "";
		while ((dmang.peek() >= '0') && (dmang.peek() <= '9')) {
			ret += dmang.getAndIncrement();
		}
		return ret;
	}
}

/******************************************************************************/
/******************************************************************************/
