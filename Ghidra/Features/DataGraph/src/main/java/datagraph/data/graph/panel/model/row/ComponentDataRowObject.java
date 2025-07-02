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
 * DataRowObject for actual DataComponents. This directly corresponds to a 
 * Data or sub Data object in a program.
 */
public class ComponentDataRowObject extends DataRowObject {
	static final int ARRAY_GROUP_SIZE = 100;
	protected Data data;

	public ComponentDataRowObject(int indentLevel, Data data, boolean isOpen) {
		super(indentLevel, isOpen);
		this.data = data;
	}

	@Override
	public boolean isExpandable() {
		return data.getNumComponents() > 0;
	}

	@Override
	public Data getData() {
		return data;
	}

	@Override
	public String getName() {
		return data.getFieldName();
	}

	@Override
	public String getValue() {
		return data.getDefaultValueRepresentation();
	}

	@Override
	public String getDataType() {
		return data.getDataType().getDisplayName();
	}

	@Override
	public boolean hasOutgoingReferences() {
		if (data.isPointer()) {
			return true;
		}
		return data.getProgram().getReferenceManager().hasReferencesFrom(data.getAddress());
	}
}
