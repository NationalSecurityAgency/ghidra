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
package ghidra.trace.util;

import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Reference;

public interface DataAdapterMinimal extends Data {
	/** Operand index for data. Will always be zero */
	int DATA_OP_INDEX = 0;
	int[] EMPTY_INT_ARRAY = new int[0];

	default String getPrimarySymbolOrDynamicName() {
		/** TODO: Use primary symbol or dynamic name as in {@link DataDB#getPathName()} */
		return "DAT_" + getAddressString(false, false);
	}

	@Override
	default int getNumOperands() {
		return 1;
	}

	@Override
	default Reference[] getValueReferences() {
		return getOperandReferences(DATA_OP_INDEX);
	}
}
