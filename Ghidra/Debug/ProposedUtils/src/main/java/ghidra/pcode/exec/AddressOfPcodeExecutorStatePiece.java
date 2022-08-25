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
package ghidra.pcode.exec;

import java.util.HashMap;
import java.util.Map;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemBuffer;

/**
 * An auxiliary state piece that reports the address of the control value
 * 
 * <p>
 * This is intended for use as the right side of a {@link PairedPcodeExecutorState} or
 * {@link PairedPcodeExecutorStatePiece}. Except for unique spaces, sets are ignored, and gets
 * simply echo back the address of the requested read. In unique spaces, the "address of" is treated
 * as the value, so that values transiting unique space can correctly have their source addresses
 * reported.
 */
public class AddressOfPcodeExecutorStatePiece
		implements PcodeExecutorStatePiece<byte[], Address> {
	private final BytesPcodeArithmetic addressArithmetic;
	private final Map<Long, Address> unique = new HashMap<>();

	/**
	 * Construct an "address of" state piece
	 * 
	 * @param isBigEndian true if the control language is big endian
	 */
	public AddressOfPcodeExecutorStatePiece(boolean isBigEndian) {
		this.addressArithmetic = BytesPcodeArithmetic.forEndian(isBigEndian);
	}

	@Override
	public PcodeArithmetic<byte[]> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<Address> getArithmetic() {
		return AddressOfPcodeArithmetic.INSTANCE;
	}

	@Override
	public void setVar(AddressSpace space, byte[] offset, int size, boolean quantize, Address val) {
		if (!space.isUniqueSpace()) {
			return;
		}
		long lOffset = addressArithmetic.toLong(offset, Purpose.STORE);
		unique.put(lOffset, val);
	}

	@Override
	public Address getVar(AddressSpace space, byte[] offset, int size, boolean quantize) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.LOAD);
		if (!space.isUniqueSpace()) {
			return space.getAddress(lOffset);
		}
		return unique.get(lOffset);
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make 'address of' concrete buffers", purpose);
	}
}
