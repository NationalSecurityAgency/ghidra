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
package ghidra.bitpatterns.info;

import java.util.List;

/**
 * This is a container class used by {@link ByteSequenceRowObject}
 */
class FilteredBytesAndDisassembly {
	private List<String> filteredBytes;
	private List<String> disassemblyString;

	FilteredBytesAndDisassembly(List<String> filteredBytes, List<String> disassembly) {
		this.filteredBytes = filteredBytes;
		this.disassemblyString = disassembly;
	}

	List<String> getFilteredBytes() {
		return filteredBytes;
	}

	List<String> getDisassembly() {
		return disassemblyString;
	}
}
