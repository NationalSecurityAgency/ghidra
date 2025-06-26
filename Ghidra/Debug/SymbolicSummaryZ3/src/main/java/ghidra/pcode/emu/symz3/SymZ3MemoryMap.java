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
package ghidra.pcode.emu.symz3;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.*;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.emu.symz3.lib.Z3MemoryWitness;
import ghidra.pcode.emu.symz3.lib.Z3MemoryWitness.WitnessType;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

/**
 * A class that can store SymZ3Values in memory
 * 
 * <p>
 * <b>NOTE: DELIBERATELY NO KNOWLEDGE OF SPACES, Languages, or "get" and "set"
 * <p>
 * The core idea is that quite often the code we are summarizing will load from memory arbitrary
 * values. We want to allow those values to exist as a unit. E.g., if the user loads 64 unknown bits
 * from an address 0xdeadbeef, we want the name of those bits to be "MEM[0xdeadbeef]:64" -- instead
 * of for example, a concat of each unknown byte. However, the 64 bit value might later be sliced
 * and diced. If we store a 64 bit symbolic value "RBX" into MEM[0xdeadbeef] and then later load
 * just an interior byte, we want to detect this. Of course if we load MEM[RCX] and we don't know
 * what RCX is, the value simply has to stay symbolic.
 * <p>
 * In terms of storage, we have two options:
 * <p>
 * first, we could have our "memvals" map always store values that are bytes. If you store a 64 bit
 * value to MEM[RAX] we would create 8 entries in our map, for MEM[RAX], MEM[RAX+1], etc.
 * <p>
 * second, we could be willing to store arbitrary sizes. This will require more searching and would
 * be problematic when we say wrote to MEM[RAX+3] having previously stored a large value at
 * MEM[RAX].
 * <p>
 * For now, we went with option 2 but then didn't implement anything tricky, so we have bugs. If we
 * move to option 1, the usecase we might worry about is something like: "{@code MEM[RAX] = RBX}"
 * how will we see this summary? We would write:
 * 
 * <pre>
 *  MEM[RAX]:8 = extract(RBX,?,?)
 *  MEM[RAX+1]:8 = extract(RBX,?,?)
 * </pre>
 * <p>
 * Note than endness would come into play, whereas right now we also sidestep this issue. Probably
 * should see if I get a simple test to pass and the simplification to work, before we fully commit
 * to option 1.
 */
public class SymZ3MemoryMap {
	// TODO ... encapsulate traversal of memvals so it can become private
	public Map<String, SymValueZ3> memvals;
	private List<Z3MemoryWitness> witnesses;

	private Language language;

	private static final boolean USE_BYTE_MODEL = true;

	public static FuncDecl<BitVecSort> buildLoad(Context ctx, int addressSize, int dataSize) {
		BitVecSort addressSort = ctx.mkBitVecSort(addressSize);
		BitVecSort dataSort = ctx.mkBitVecSort(dataSize);
		return ctx.mkFuncDecl("load_" + addressSize + "_" + dataSize, addressSort, dataSort);
	}

	public SymZ3MemoryMap(Language language) {
		memvals = new HashMap<String, SymValueZ3>();
		this.language = language;
		witnesses = new ArrayList<Z3MemoryWitness>();
	}

	protected Entry<String, String> valuationForMemval(Context ctx, Z3InfixPrinter z3p,
			Entry<String, SymValueZ3> entry) {
		String address = entry.getKey();
		SymValueZ3 vv = entry.getValue();
		BitVecExpr addressExpr = SymValueZ3.deserializeBitVecExpr(ctx, address);
		if (vv == null) {
			return Map.entry("MEM " + z3p.infixWithBrackets(addressExpr), "null");
		}
		BitVecExpr v = vv.getBitVecExpr(ctx);
		if (v == null) {
			return Map.entry("MEM " + z3p.infixWithBrackets(addressExpr), "null (?) " + vv);
		}
		v = (BitVecExpr) v.simplify();
		int bitSize = v.getSortSize();
		String sizeString = ":" + Integer.toString(bitSize);
		return Map.entry("MEM " + z3p.infixWithBrackets(addressExpr) + sizeString,
			z3p.infixUnsigned(v));
	}

	protected Entry<String, String> valuationForWitness(Context ctx, Z3InfixPrinter z3p,
			Set<BitVecExpr> reported, Z3MemoryWitness w) {
		BitVecExpr addressExpr = w.address().getBitVecExpr(ctx);
		if (!reported.add(addressExpr)) {
			return null;
		}
		SymValueZ3 vv = load(w.address(), w.bytesMoved(), false);
		BitVecExpr v = vv.getBitVecExpr(ctx);
		if (v == null) {
			return Map.entry("MEM " + z3p.infixWithBrackets(addressExpr), "null (?)");
		}
		v = (BitVecExpr) v.simplify();
		int bitSize = v.getSortSize();
		String sizeString = ":" + Integer.toString(bitSize);
		return Map.entry("MEM " + z3p.infixWithBrackets(addressExpr) + sizeString,
			z3p.infixUnsigned(v));
	}

	public String printableSummary() {
		StringBuilder result = new StringBuilder();
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			for (Map.Entry<String, SymValueZ3> entry : memvals.entrySet()) {
				String address = entry.getKey();
				SymValueZ3 vv = memvals.get(address);
				BitVecExpr addressExpr = SymValueZ3.deserializeBitVecExpr(ctx, address);
				if (vv == null) {
					result.append("MEM " + z3p.infixWithBrackets(addressExpr) + " is null");
					result.append(System.lineSeparator());
				}
				else {
					BitVecExpr v = vv.getBitVecExpr(ctx);
					if (v == null) {
						result.append("MEM " + z3p.infixWithBrackets(addressExpr) +
							" is null (?)" + memvals.get(address));
						result.append(System.lineSeparator());
					}
					else {
						v = (BitVecExpr) v.simplify();
						int bitSize = v.getSortSize();
						String sizeString = ":" + Integer.toString(bitSize);
						result.append("MEM " + z3p.infixWithBrackets(addressExpr) + sizeString +
							" = " + z3p.infixUnsigned(v));
						result.append(System.lineSeparator());
					}
				}
			}

			ArrayList<BitVecExpr> reported = new ArrayList<BitVecExpr>();
			for (Z3MemoryWitness w : witnesses) {
				BitVecExpr addressExpr = w.address().getBitVecExpr(ctx);
				if (reported.contains(addressExpr)) {
					continue;
				}
				reported.add(addressExpr);
				SymValueZ3 value = load(w.address(), w.bytesMoved(), false);
				BitVecExpr vexpr = value.getBitVecExpr(ctx);
				if (vexpr == null) {
					result.append("MEM " + z3p.infixWithBrackets(addressExpr) + " is null (?)");
					result.append(System.lineSeparator());
				}
				else {
					BitVecExpr v = (BitVecExpr) vexpr.simplify();
					int bitSize = v.getSortSize();
					String sizeString = ":" + Integer.toString(bitSize);
					result.append("MEM " + z3p.infixWithBrackets(addressExpr) + sizeString +
						" = " + z3p.infixUnsigned(v));
					result.append(System.lineSeparator());
				}
			}
		}
		return result.toString();
	}

	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		Stream<Entry<String, String>> forMemVals = memvals.entrySet().stream().map(entry -> {
			return valuationForMemval(ctx, z3p, entry);
		});
		Set<BitVecExpr> reported = new HashSet<>();
		Stream<Entry<String, String>> forWitnesses = witnesses.stream().mapMulti((w, mapper) -> {
			Entry<String, String> result = valuationForWitness(ctx, z3p, reported, w);
			if (result != null) {
				mapper.accept(result);
			}
		});
		return Stream.concat(forMemVals, forWitnesses);
	}

	public SymValueZ3 load(SymValueZ3 offset, int size, boolean addWitness) {
		try (Context ctx = new Context()) {
			if (addWitness) {
				witnesses.add(new Z3MemoryWitness(offset, size, WitnessType.LOAD));
			}
			BitVecExpr address = offset.getBitVecExpr(ctx);

			if (!USE_BYTE_MODEL) {
				// this is the primary disadvantage of the non-byte based model.  on a load, the value we need to build 
				// might not simply be stored... it could even be in other locations in the store... so this is really
				// difficult to get right, but super easy if you are willing to not care...
				if (memvals.containsKey(offset.bitVecExprString)) {
					// TODO Ignoring the SIZE... that might be really important... TO DO
					SymValueZ3 value = memvals.get(offset.bitVecExprString);
					assert value != null;
					BitVecExpr valueb = value.getBitVecExpr(ctx);
					if (valueb.getSortSize() != size * 8) {
						// could do the stupid thing and just return a symbolic value...
						Msg.error(this, "Performed a load of " + size +
							" bytes but stored value was of size: " + valueb.getSortSize());
						throw new AssertionError(
							"size based memory model needs more code to fetch a portion of what was written");
					}
					return value;
				}
				// this symbolic load might totally miss out on the fact that we actually know more
				FuncDecl<BitVecSort> f = buildLoad(ctx, address.getSortSize(), size * 8);
				BitVecExpr expression = (BitVecExpr) ctx.mkApp(f, address);

				return new SymValueZ3(ctx, expression);

			}
			// essentially, we load each byte separately ... each byte may or may not have a known value.
			// we have to assume that whatever our offset is, when we add one to it, the result is how it was stored.
			// that might not technically be true.  Ideally there would be some sort of normalization.
			// NOTE:  CURRENTLY IGNORING ENDNESS
			List<BitVecExpr> result_pieces = new ArrayList<BitVecExpr>();
			BitVecExpr one = ctx.mkBV(1, address.getSortSize());
			BitVecExpr byteAddress = address;
			for (int byte_offset = 0; byte_offset < size; byte_offset = byte_offset + 1) {
				if (byte_offset > 0) {
					byteAddress = ctx.mkBVAdd(byteAddress, one);
				}
				byteAddress = (BitVecExpr) byteAddress.simplify(); // a form of normalization
				String byteAddressAsString = SymValueZ3.serialize(ctx, byteAddress);
				if (memvals.containsKey(byteAddressAsString)) {
					result_pieces.add(memvals.get(byteAddressAsString).getBitVecExpr(ctx));
				}
				else {
					FuncDecl<BitVecSort> f = buildLoad(ctx, address.getSortSize(), 8);
					BitVecExpr expression = (BitVecExpr) ctx.mkApp(f, byteAddress);
					result_pieces.add(expression);
				}
			}
			BitVecExpr result = null;
			// for the other ENDIAN, don't reverse
			if (!language.isBigEndian()) {
				Collections.reverse(result_pieces);
			}
			for (BitVecExpr piece : result_pieces) {
				if (result == null) {
					result = piece;
				}
				else {
					result = ctx.mkConcat(result, piece);
				}
			}
			return new SymValueZ3(ctx, result);
		}
	}

	public void store(SymValueZ3 offset, int size, SymValueZ3 val) {
		witnesses.add(new Z3MemoryWitness(offset, size, WitnessType.STORE));
		try (Context ctx = new Context()) {
			BitVecExpr bval = val.getBitVecExpr(ctx);
			BitVecExpr address = offset.getBitVecExpr(ctx);
			assert bval.getSortSize() == size * 8;
			if (!USE_BYTE_MODEL) {
				// this is the primary advantage of the non-byte based model, storage is super easy
				Msg.debug(this, "set memory location " + address + " size " + size + " to " + val);
				memvals.put(offset.bitVecExprString, val);
			}
			else {
				// for the byte-based model, we simply must store each byte separately.
				// NOTE: CURRENTLY IGNORING ENDNeSS
				BitVecExpr one = ctx.mkBV(1, address.getSortSize());
				BitVecExpr byteAddress = address;
				for (int byte_offset = 0; byte_offset < size; byte_offset = byte_offset + 1) {
					if (byte_offset > 0) {
						byteAddress = ctx.mkBVAdd(byteAddress, one);
					}
					byteAddress = (BitVecExpr) byteAddress.simplify(); // a form of normalization
					String byteAddressAsString = SymValueZ3.serialize(ctx, byteAddress);

					int bit_size = size * 8;
					int high;
					int low;
					if (language.isBigEndian()) {
						high = bit_size - (byte_offset * 8) - 1;
						low = bit_size - ((byte_offset + 1) * 8);
					}
					else {
						high = byte_offset * 8 + 7;
						low = byte_offset * 8;
					}
					BitVecExpr valportion = ctx.mkExtract(high, low, bval);
					memvals.put(byteAddressAsString, new SymValueZ3(ctx, valportion));
				}
			}
		}
	}

	public boolean hasValueFor(SymValueZ3 offset, int size) {
		// TODO need to think about the size
		//BitVecExpr address = offset.getBitVecExpr();
		if (memvals.containsKey(offset.bitVecExprString)) {
			//SymValueZ3 result = memvals.get(address);
			// TODO could assert size is what we request??
			return true;
		}
		return false;
	}
}
