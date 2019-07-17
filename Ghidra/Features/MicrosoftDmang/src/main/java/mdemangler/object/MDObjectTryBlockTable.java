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
 * This class represents a MSFT <b><code>__tryblocktable$</code></b> (prefix) symbol.  We have
 *  created this object and the <b><code>MDObjectReserved</code></b> type from which it is
 *  derived.  We do not know much about this object yet.
 *<p>
 * We have seen symbols such as:<pre>
 *  __tryblocktable$?test_eh1@@YAHXZ
 * </pre>
 */
public class MDObjectTryBlockTable extends MDObjectReserved {
	private MDObjectCPP objectCPP;

	public MDObjectTryBlockTable(MDMang dmang) {
		super(dmang);
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		dmang.appendString(builder, "[TryblockTable]{" + objectCPP + "}");
	}

	@Override
	protected void parseInternal() throws MDException {
		objectCPP = new MDObjectCPP(dmang);
		objectCPP.parse();
		// MDMANG SPECIALIZATION USED.
		objectCPP = dmang.getEmbeddedObject(objectCPP);
	}
}

/******************************************************************************/
/******************************************************************************/
