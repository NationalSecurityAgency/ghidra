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
package ghidra.pcode.emu.taint.state;

import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.AbstractPropertyBasedPieceHandler;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.taint.model.TaintSet;
import ghidra.taint.model.TaintVec;

/**
 * The piece handler for {@link TaintVec}
 * 
 * <p>
 * This contains the logic for integrating the Taint emulator with traces. That is, it is the
 * mechanism that loads previous taint analysis from a trace and stores new results back into the
 * trace. The object passed into these methods as {@code piece} is almost certainly a
 * {@link TaintPcodeExecutorStatePiece}, but not necessarily. As a matter of best practice, it
 * should not be necessary to cast. The given {@link PcodeExecutorStatePiece} interface should be
 * sufficient as internals can often be reached via
 * {@link PcodeExecutorStatePiece#getVarInternal(AddressSpace, long, int, Reason)}.
 */
public class TaintPieceHandler extends AbstractPropertyBasedPieceHandler<byte[], TaintVec, String> {
	/**
	 * The name we will use for the property map
	 */
	public static final String NAME = "Taint";

	@Override
	public Class<byte[]> getAddressDomain() {
		return byte[].class;
	}

	@Override
	public Class<TaintVec> getValueDomain() {
		return TaintVec.class;
	}

	@Override
	protected String getPropertyName() {
		return NAME;
	}

	@Override
	protected Class<String> getPropertyType() {
		return String.class;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The super class takes care of visiting each property map entry that may be involved. This
	 * method gets invoked for each one found, identifying the range to which the property value
	 * applies and the value itself. <b>IMPORTANT:</b> This implementation must still ensure it only
	 * modifies addresses that are not yet initialized. The set of such addresses is given by
	 * {@code limit}. Thus, we have the if-else to determine whether or not the found property entry
	 * is wholly contained within that limit. If not, then we have to piecemeal it.
	 * <p>
	 * To insert each resulting entry into the state piece, we use
	 * {@link PcodeExecutorStatePiece#setVarInternal(AddressSpace, long, int, Object)}, so that we
	 * do not issue any follow-on callbacks.
	 */
	@Override
	protected void decodeFrom(PcodeExecutorStatePiece<byte[], TaintVec> piece, AddressSetView limit,
			AddressRange range, String propertyValue) {
		TaintVec vec = TaintVec.copies(TaintSet.parse(propertyValue), (int) range.getLength());
		if (limit.contains(range.getMaxAddress(), range.getMaxAddress())) {
			piece.setVarInternal(range.getAddressSpace(), range.getMinAddress().getOffset(),
				vec.length, vec);
		}
		else {
			for (AddressRange sub : limit.intersectRange(range.getMinAddress(),
				range.getMaxAddress())) {
				int offset = (int) sub.getMinAddress().subtract(range.getMinAddress());
				TaintVec sv = vec.sub(offset, (int) sub.getLength());
				piece.setVarInternal(sub.getAddressSpace(), sub.getMinAddress().getOffset(),
					sv.length, sv);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The super class takes care of iterating over the entries in the state piece, using
	 * {@link PcodeExecutorStatePiece#getNextEntryInternal(AddressSpace, long)}. In our case, since
	 * we coalesce identically-tainted contiguous bytes, serialization is fairly straightforward.
	 * The one nuances is that we'd rather not waste entries for addresses without any taint, and so
	 * we check for that and use {@code null} instead, which will cause the shim to clear the
	 * property on those addresses.
	 */
	@Override
	protected void encodeInto(PcodeTracePropertyAccess<String> property, AddressRange range,
			TaintVec value) {
		Address min = range.getMinAddress();
		for (int i = 0; i < value.length; i++) {
			TaintSet s = value.get(i);
			Address address = min.add(i);
			if (s.isEmpty()) {
				property.clear(new AddressRangeImpl(address, address));
			}
			else {
				property.put(address, s.toString());
			}
		}
	}
}
