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
package sarif.export.trees;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.listing.ProgramFragment;

public class ExtFragment implements IsfObject {

	String name;
	List<ExtFragmentRange> ranges = new ArrayList<>();

	public ExtFragment(ProgramFragment f, List<Object> visited) {
		this.name = f.getName();
		visited.add(f);
		AddressRangeIterator iter = f.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			ExtFragmentRange r = new ExtFragmentRange(range);
			ranges.add(r);
		}
	}

}
