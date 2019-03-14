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
package ghidra.app.util.opinion;

import ghidra.program.model.address.*;

import java.util.*;

public class AddressSetPartitioner implements Iterable<AddressRange> {
	private static final Comparator<AddressRange> MIN_ADDRESS_ASC = new Comparator<AddressRange>() {
		@Override
		public int compare(AddressRange lhs, AddressRange rhs) {
			return lhs.getMinAddress().compareTo(rhs.getMinAddress());
		}
	};

	private final ArrayList<AddressRange> addressRangeCache;
	private final HashMap<AddressRange, byte[]> rangeMapCache;

	public AddressSetPartitioner(AddressSet set, Map<AddressRange, byte[]> rangeMap,
			Set<Address> partitionSet) {
		ArrayList<AddressRange> ranges = new ArrayList<AddressRange>();
		ArrayList<Address> partitionsMaster = new ArrayList<Address>(partitionSet);
		Collections.sort(partitionsMaster);
		ArrayList<Address> partitions = new ArrayList<Address>(partitionsMaster);
		AddressRangeIterator addressRanges = set.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			ranges.add(addressRange);
		}
		Collections.sort(ranges, MIN_ADDRESS_ASC);
		addressRangeCache = new ArrayList<AddressRange>();
		while (!ranges.isEmpty()) {
			AddressRange range = ranges.get(0);
			ranges.remove(0);
			boolean split = false;
			for (Address part : partitions) {
				if (range.contains(part) && !part.equals(range.getMinAddress())) {
					split = true;
					Address firstMax = part.previous();
					AddressRange first = new AddressRangeImpl(range.getMinAddress(), firstMax);
					AddressRange second = new AddressRangeImpl(part, range.getMaxAddress());
					addressRangeCache.add(first);
					ranges.add(0, second);
					partitions.remove(part);
					break;
				}
			}
			if (!split) {
				addressRangeCache.add(range);
			}
		}

		partitions = new ArrayList<Address>(partitionsMaster);
		HashMap<AddressRange, byte[]> original = new HashMap<AddressRange, byte[]>(rangeMap);
		rangeMapCache = new HashMap<AddressRange, byte[]>();
		while (!original.isEmpty()) {
			AddressRange range = original.keySet().iterator().next();
			byte[] bytes = original.get(range);
			original.remove(range);
			boolean split = false;
			for (Address part : partitions) {
				if (range.contains(part) && !part.equals(range.getMinAddress())) {
					split = true;
					Address firstMax = part.previous();
					AddressRange first = new AddressRangeImpl(range.getMinAddress(), firstMax);
					AddressRange second = new AddressRangeImpl(part, range.getMaxAddress());
					byte[] firstBytes = new byte[(int) first.getLength()];
					byte[] secondBytes = new byte[(int) second.getLength()];
					System.arraycopy(bytes, 0, firstBytes, 0, firstBytes.length);
					System.arraycopy(bytes, firstBytes.length, secondBytes, 0, secondBytes.length);
					rangeMapCache.put(first, firstBytes);
					original.put(second, secondBytes);
					partitions.remove(part);
					break;
				}
			}
			if (!split) {
				rangeMapCache.put(range, bytes);
			}
		}
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return Collections.unmodifiableList(addressRangeCache).iterator();
	}

	public Map<AddressRange, byte[]> getPartionedRangeMap() {
		return Collections.unmodifiableMap(rangeMapCache);
	}
}
