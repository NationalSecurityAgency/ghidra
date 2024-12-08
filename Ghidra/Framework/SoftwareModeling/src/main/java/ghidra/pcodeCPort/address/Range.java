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
package ghidra.pcodeCPort.address;

import java.io.PrintStream;

import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.translate.Translate;

public class Range implements Comparable<Range> {
	private AddrSpace spc; // Space containing range

	private long first; // Inclusive bounds of range

	private long last;

	public Range(AddrSpace s, long f, long l) {
		spc = s;
		first = f;
		last = l;
	}

	public Range() {
	}

	public AddrSpace getSpace() {
		return spc;
	}

	public long getFirst() {
		return first;
	}

	public long getLast() {
		return last;
	}

	public Address getFirstAddr() {
		return new Address(spc, first);
	}

	public Address getLastAddr() {
		return new Address(spc, last);
	}

	@Override
	public int compareTo(Range other) {
		int result = spc.compareTo(other.spc);
		if (result != 0) {
			return result;
		}
		return AddressUtils.unsignedCompare(first, other.first);
	}

	void printBounds(PrintStream s) {
		s.append(spc.getName());
		s.append(": ");
		s.append(Long.toHexString(first));
		s.append('-');
		s.append(Long.toHexString(last));
	}

	//	 Get the last address +1, updating the space, or returning
	public Address getLastAddrOpen(Translate trans) {
		// the extremal address if necessary
		AddrSpace curspc = spc;
		long curlast = last;
		if (curlast == curspc.getMask()) {
			curspc = trans.getNextSpaceInOrder(curspc);
			curlast = 0;
		}
		else {
			curlast += 1;
		}
		if (curspc == null) {
			return new Address(Address.mach_extreme.m_maximal);
		}
		return new Address(curspc, curlast);
	}

}
