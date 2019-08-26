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
 * Address Space for (intel) 16-bit protected mode programs. This space produces
 * SegmentedAddress objects whose underlying (flat) offset encodes both the
 * segment and the segment offset without losing information. There is no possibility
 * of alternate encodings for a single address as with real-mode.
 */
public class ProtectedAddressSpace extends SegmentedAddressSpace {

	private final static int PROTECTEDMODE_SIZE = 32;
	private final static int PROTECTEDMODE_OFFSETSIZE = 16;

	private int offsetSize;		// Number of bits in the segment offset
	private long offsetMask;	// Mask for retrieving the segment offset

	public ProtectedAddressSpace(String name, int unique) {
		super(name, PROTECTEDMODE_SIZE, unique);
		offsetSize = PROTECTEDMODE_OFFSETSIZE;
		offsetMask = 1;
		offsetMask <<= offsetSize;
		offsetMask -= 1;
		maxAddress = getUncheckedAddress(maxOffset);
	}

	@Override
	protected long getFlatOffset(int segment, long offset) {
		long res = segment;
		res <<= offsetSize;
		res += offset;
		return res;
	}

	@Override
	protected int getDefaultSegmentFromFlat(long flat) {
		return (int) (flat >>> offsetSize);
	}

	@Override
	protected long getDefaultOffsetFromFlat(long flat) {
		return (flat & offsetMask);
	}

	@Override
	protected long getOffsetFromFlat(long flat, int segment) {
		return (flat & offsetMask);		// segment does not affect the offset
	}

	@Override
	protected SegmentedAddress getAddressInSegment(long flat, int preferredSegment) {
		return null;	// The segment cannot be changed as the flat explicitly encodes it
	}

	@Override
	public int getNextOpenSegment(Address addr) {
		int res = getDefaultSegmentFromFlat(addr.getOffset());
		// Advance the selector by 8, accounting for the descriptor table bit and the privilege level bits
		res = (res + 8) & 0xfff8;
		return res;
	}
}
