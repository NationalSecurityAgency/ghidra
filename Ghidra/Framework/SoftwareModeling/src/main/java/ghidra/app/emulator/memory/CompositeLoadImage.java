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
package ghidra.app.emulator.memory;

import java.util.*;

import ghidra.pcode.memstate.MemoryPage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

public class CompositeLoadImage implements MemoryLoadImage {

	private List<MemoryLoadImage> providers = new ArrayList<MemoryLoadImage>();
	private HashMap<MemoryLoadImage, AddressSetView> addrSets =
		new HashMap<MemoryLoadImage, AddressSetView>();

	public void addProvider(MemoryLoadImage provider, AddressSetView view) {
		if (view == null) {
			providers.add(providers.size(), provider);
		}
		else {
			providers.add(0, provider);
		}
		addrSets.put(provider, view);
	}

	@Override
	public byte[] loadFill(byte[] buf, int size, Address addr, int bufOffset,
			boolean generateInitializedMask) {
		// Warning: this implementation assumes that the memory page (specified by addr and size)
		// will only correspond to a single program image.
		Address endAddr = addr.add(size - 1);
		for (MemoryLoadImage provider : providers) {
			AddressSetView view = addrSets.get(provider);
			if (view == null || view.intersects(addr, endAddr)) {
				return provider.loadFill(buf, size, addr, bufOffset, generateInitializedMask);
			}
		}
		return generateInitializedMask ? MemoryPage.getInitializedMask(size, false) : null;
	}

	@Override
	public void writeBack(byte[] bytes, int size, Address addr, int offset) {
		// Warning: this implementation assumes that the memory page (specified by addr and size)
		// will only correspond to a single program image.
		Address endAddr = addr.add(size - 1);
		for (MemoryLoadImage provider : providers) {
			AddressSetView view = addrSets.get(provider);
			if (view == null || view.intersects(addr, endAddr)) {
				provider.writeBack(bytes, size, addr, offset);
			}
		}
	}

	@Override
	public void dispose() {
		for (MemoryLoadImage provider : providers) {
			provider.dispose();
		}
	}

}
