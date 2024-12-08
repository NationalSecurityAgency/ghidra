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
package ghidra.program.model.address;

/**
 * {@link SingleRangeOverlayAddressSpace} provides a simple immutable overlay space
 * which consists of a single memory offset range.
 */
public class SingleRangeOverlayAddressSpace extends OverlayAddressSpace {

	private String name;
	private long min;
	private long max;
	private AddressSetView overlaySet;

	/**
	 * Construct a single range overlay address space.
	 * NOTE: The same name should not be used more than once within a given {@link AddressFactory}.
	 * @param name overlay space name
	 * @param baseSpace overlayed base space
	 * @param unique unique index number
	 * @param min min address offset
	 * @param max max address offset
	 * @param orderedKey ordered key which is used during comparison with other overlays.  Within
	 * program-based implementation (i.e., ProgramOverlayAddressSpace) this is auto-generated based 
	 * upon the initial name and must be unique within the associated AddressFactory which does not
	 * exist for this test implementation.
	 */
	public SingleRangeOverlayAddressSpace(String name, AddressSpace baseSpace, int unique, long min,
			long max, String orderedKey) {
		super(baseSpace, unique, orderedKey);
		this.name = name;
		this.min = min;
		this.max = max;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean contains(long offset) {
		return Long.compareUnsigned(offset, min) >= 0 && Long.compareUnsigned(offset, max) <= 0;
	}

	@Override
	public AddressSetView getOverlayAddressSet() {
		if (overlaySet == null) {
			AddressSet set = new AddressSet();
			AddressRange range = new AddressRangeImpl(getAddressInThisSpaceOnly(min),
				getAddressInThisSpaceOnly(max));
			set.add(range);
			overlaySet = set;
		}
		return overlaySet;
	}
}
