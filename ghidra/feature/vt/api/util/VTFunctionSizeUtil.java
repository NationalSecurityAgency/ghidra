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
package ghidra.feature.vt.api.util;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

public class VTFunctionSizeUtil {
	private VTFunctionSizeUtil() {
		// non-instantiable
	}

	public static AddressSetView minimumSizeFunctionFilter(Program program,
			AddressSetView originalAddressSet, int minimumFunctionSize, TaskMonitor monitor) {
		AddressSet result = new AddressSet(originalAddressSet);
		FunctionIterator ii = program.getFunctionManager().getFunctions(originalAddressSet, true);
		while (ii.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = ii.next();
			AddressSetView body = function.getBody();
			if (function.isThunk() || body.getNumAddresses() < minimumFunctionSize) {
				AddressRangeIterator addressRanges = body.getAddressRanges();
				for (AddressRange addressRange : addressRanges) {
					result.delete(addressRange);
				}
			}
		}
		return result;
	}
}
