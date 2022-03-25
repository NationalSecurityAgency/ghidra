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
package ghidra.app.extension.datatype.finder;

import java.util.List;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.data.DataType;

public class ReturnTypeDR extends DecompilerReference {

	ReturnTypeDR(ClangLine line, ClangTypeToken type) {
		super(line, type);
	}

	@Override
	public void accumulateMatches(DataType dt, FieldMatcher fieldMatcher,
			List<DataTypeReference> results) {

		if (!fieldMatcher.isIgnored()) {
			return; // Return Types do not have any field usage
		}

		DataType myDt = getDataType();
		if (myDt == null) {
			return;
		}

		if (isEqual(dt, myDt)) {
			results.add(
				new DataTypeReference(myDt, null, getFunction(), getAddress(), getContext()));
		}
	}
}
