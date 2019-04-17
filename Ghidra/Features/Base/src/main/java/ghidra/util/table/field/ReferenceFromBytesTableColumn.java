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
package ghidra.util.table.field;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.program.model.address.Address;

/**
 * This table field displays the bytes of the code unit at the FromAddress 
 * for the reference or possible reference address pair
 * associated with a row in the table.
 */
public class ReferenceFromBytesTableColumn extends AbstractReferenceBytesTableColumn {

	public ReferenceFromBytesTableColumn() {
		// required for reflective purposes
	}

	@Override
	public String getColumnName() {
		return getColumnNamePrefix() + "Bytes";
	}

	@Override
	protected String getColumnNamePrefix() {
		return "From ";
	}

	@Override
	protected Address getAddress(ReferenceAddressPair pair) {
		return pair.getSource();
	}
}
