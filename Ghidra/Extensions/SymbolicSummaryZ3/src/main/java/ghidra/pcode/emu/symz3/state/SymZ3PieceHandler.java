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
package ghidra.pcode.emu.symz3.state;

import java.util.*;

import com.microsoft.z3.Context;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.AbstractPropertyBasedPieceHandler;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.symz3.model.SymValueZ3;

public class SymZ3PieceHandler
		extends AbstractPropertyBasedPieceHandler<SymValueZ3, SymValueZ3, String> {
	public static final String NAME = "SymValueZ3";

	private record SymZ3Varnode(AddressSpace space, String offset, int size) {
		public SymZ3Varnode(AddressSpace space, SymValueZ3 offset, int size) {
			this(space, offset.bitVecExprString, size);
		}

		public SymValueZ3 offset(Context ctx) {
			return new SymValueZ3(ctx, SymValueZ3.deserializeBitVecExpr(ctx, offset));
		}
	}

	private final Map<PcodeThread<?>, Set<SymZ3Varnode>> abstractWritten = new HashMap<>();

	@Override
	public Class<SymValueZ3> getAddressDomain() {
		return SymValueZ3.class;
	}

	@Override
	public Class<SymValueZ3> getValueDomain() {
		return SymValueZ3.class;
	}

	@Override
	protected String getPropertyName() {
		return NAME;
	}

	@Override
	protected Class<String> getPropertyType() {
		return String.class;
	}

	@Override
	public void abstractWritten(PcodeTraceDataAccess acc, AddressSet written, PcodeThread<?> thread,
			PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> piece, AddressSpace space,
			SymValueZ3 offset, int length, SymValueZ3 value) {
		try {
			Address address = piece.getAddressArithmetic().toAddress(offset, space, Purpose.STORE);
			dataWritten(acc, written, thread, piece, address, length, value);
		}
		catch (ConcretionError e) {
			abstractWritten.computeIfAbsent(thread, t -> new HashSet<>())
					.add(new SymZ3Varnode(space, offset, length));
		}
	}

	@Override
	public int abstractReadUninit(PcodeTraceDataAccess acc, PcodeThread<?> thread,
			PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> piece, AddressSpace space,
			SymValueZ3 offset, int length) {
		String string = acc.getPropertyAccess(NAME, String.class).get(Address.NO_ADDRESS);
		if (string == null) {
			return 0;
		}
		return Unfinished.TODO("need to implement extraction from: " + string);
	}

	@Override
	protected void decodeFrom(PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> piece,
			AddressSetView limit, AddressRange range, String propertyValue) {
		/**
		 * NOTE: We're ignoring limit here, because we've not really implemented byte-wise property
		 * access.
		 */
		SymValueZ3 result = SymValueZ3.parse(propertyValue);
		piece.setVarInternal(range.getAddressSpace(), range.getMinAddress().getOffset(),
			(int) range.getLength(), result);
	}

	@Override
	public void writeDown(PcodeTraceDataAccess into, PcodeThread<?> thread,
			PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> piece, AddressSetView written) {
		super.writeDown(into, thread, piece, written);
		Set<SymZ3Varnode> symWritten = abstractWritten.get(thread);
		if (symWritten == null) {
			return;
		}
		StringBuffer buf = new StringBuffer();
		try (Context ctx = new Context()) {
			for (SymZ3Varnode vn : symWritten) {
				SymValueZ3 offset = vn.offset(ctx);
				SymValueZ3 value = piece.getVarInternal(vn.space, offset, vn.size, Reason.INSPECT);
				buf.append("::");
				buf.append(offset);
				buf.append("<==>");
				buf.append(value.serialize());
			}
		}
		/**
		 * NOTE: This won't work for threads, but then again, how would one address a register
		 * abstractly?
		 */
		String val = buf.isEmpty() ? null : buf.toString();
		into.getPropertyAccess(NAME, String.class).put(Address.NO_ADDRESS, val);
	}

	@Override
	protected void encodeInto(PcodeTracePropertyAccess<String> property, AddressRange range,
			SymValueZ3 value) {
		property.put(range.getMinAddress(), value.serialize());
	}
}
