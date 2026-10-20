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
package ghidra.program.model.lang;

import java.util.ArrayList;

import ghidra.program.model.data.DataTypeManager;

/**
 * A list of resources describing possible storage locations for a function's return value,
 * and a strategy for selecting a storage location based on data-types in a function signature.
 *
 * This is based solely upon the strategy than its parent class.  It's inclusion is just to mirror it's
 * partner class ParamListPascal.
 */
public class ParamListPascalOut extends ParamListStandardOut {

	@Override
	public void assignMap(PrototypePieces proto, DataTypeManager dtManager, int[] status,
			ArrayList<ParameterPieces> res, boolean addAutoParams) {
		super.assignMap(proto, dtManager, status, res, addAutoParams);
	}

}
