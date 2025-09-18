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
package datagraph.data.graph.panel.model.row;

import ghidra.program.model.listing.Data;

/**
 * DataRowObject for groups of array elements. Because arrays can be large they are recursively
 * grouped.
 */
public class ArrayGroupDataRowObject extends DataRowObject {

	private String name;
	private Data data;

	ArrayGroupDataRowObject(Data data, int startIndex, int length, int indentLevel,
			boolean isOpen) {
		super(indentLevel, isOpen);
		this.data = data;
		this.name = "[" + startIndex + " - " + (startIndex + length - 1) + "]";
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getValue() {
		return "";
	}

	@Override
	public String getDataType() {
		return "";
	}

	@Override
	public boolean isExpandable() {
		return true;
	}

	@Override
	public Data getData() {
		return data;
	}

}
