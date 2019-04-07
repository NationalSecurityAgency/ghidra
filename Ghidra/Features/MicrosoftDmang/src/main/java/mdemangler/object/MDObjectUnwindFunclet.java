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

import mdemangler.*;

/**
 * This class represents a MSFT <b><code>__unwindfunclet$</code></b> (prefix) symbol.  We have
 *  created this object and the <b><code>MDObjectReserved</code></b> type from which it is
 *  derived.  We do not know much about this object yet.
 *<p>
 * We have seen symbols such as:<pre>
 *  __unwindfunclet$?test_eh2@@YAHXZ$4
 * </pre>
*/
public class MDObjectUnwindFunclet extends MDObjectReserved {
	private String digits;
	private MDParsableItem internalItem;

	public MDObjectUnwindFunclet(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.appendString(builder,
			"[UnwindFunclet," + digits + "]{" + internalItem + "}");
	}

	@Override
	protected void parseInternal() throws MDException {
		internalItem = MDMangObjectParser.parse(dmang);
		internalItem.parse();
		dmang.increment(); // '$'
		//Here, we have seen $9 and $10 (two digits for $10).
		//TODO: forward programming to test beyond one digit.
		digits = parseDigits(dmang);
	}
}

/******************************************************************************/
/******************************************************************************/
