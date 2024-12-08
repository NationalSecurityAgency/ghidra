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
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;

/**
 * An auxiliary state piece that reports the location of the control value
 * 
 * <p>
 * This is intended for use as the right side of a {@link PairedPcodeExecutorState} or
 * {@link PairedPcodeExecutorStatePiece}. Except for unique spaces, sets are ignored, and gets
 * simply echo back the location of the requested read. In unique spaces, the "location" is treated
 * as the value, so that values transiting unique space can correctly have their source locations
 * reported.
 */
public class LocationPcodeExecutorStatePiece
		implements PcodeExecutorStatePiece<byte[], ValueLocation> {
	private final Language language;
	private final LocationPcodeArithmetic arithmetic;
	private final BytesPcodeArithmetic addressArithmetic;
	private final Map<Long, ValueLocation> unique;

	/**
	 * Construct a "location" state piece
	 * 
	 * @param language the language of the machine
	 */
	public LocationPcodeExecutorStatePiece(Language language) {
		this.language = language;
		boolean isBigEndian = language.isBigEndian();
		this.arithmetic = LocationPcodeArithmetic.forEndian(isBigEndian);
		this.addressArithmetic = BytesPcodeArithmetic.forEndian(isBigEndian);
		this.unique = new HashMap<>();
	}

	protected LocationPcodeExecutorStatePiece(Language language,
			BytesPcodeArithmetic addressArithmetic, Map<Long, ValueLocation> unique) {
		this.language = language;
		this.arithmetic = LocationPcodeArithmetic.forEndian(language.isBigEndian());
		this.addressArithmetic = addressArithmetic;
		this.unique = unique;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public PcodeArithmetic<byte[]> getAddressArithmetic() {
		return addressArithmetic;
	}

	@Override
	public PcodeArithmetic<ValueLocation> getArithmetic() {
		return arithmetic;
	}

	@Override
	public LocationPcodeExecutorStatePiece fork() {
		return new LocationPcodeExecutorStatePiece(language, addressArithmetic,
			new HashMap<>(unique));
	}

	@Override
	public void setVar(AddressSpace space, byte[] offset, int size, boolean quantize,
			ValueLocation val) {
		if (!space.isUniqueSpace()) {
			return;
		}
		// TODO: size is not considered
		long lOffset = addressArithmetic.toLong(offset, Purpose.STORE);
		unique.put(lOffset, val);
	}

	@Override
	public ValueLocation getVar(AddressSpace space, byte[] offset, int size, boolean quantize,
			Reason reason) {
		long lOffset = addressArithmetic.toLong(offset, Purpose.LOAD);
		if (!space.isUniqueSpace()) {
			return ValueLocation.fromVarnode(space.getAddress(lOffset), size);
		}
		return unique.get(lOffset);
	}

	@Override
	public Map<Register, ValueLocation> getRegisterValues() {
		return Map.of();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new ConcretionError("Cannot make 'location' concrete buffers", purpose);
	}

	@Override
	public void clear() {
		unique.clear();
	}
}
