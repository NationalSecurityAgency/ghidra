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
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;

/**
 * A class that can store SymZ3Values in registers /*
 * <p>
 * <b>NOTE:</b> DELIBERATELY NO KNOWLEDGE OF SPACES, Languages, or "get" and "set"
 */
public class SymZ3RegisterMap {

	// TODO:  make this be private and provide appropriate methods
	// in the map, all registers are base registers.
	public Map<Register, SymValueZ3> regvals = new HashMap<Register, SymValueZ3>();

	//private List<String> createdSymbolics = new ArrayList<String>();
	private final Set<String> registerNamesRead = new HashSet<String>();
	private final Set<String> registerNamesUpdated = new HashSet<String>();
	private final Map<String, Register> knownRegisters = new HashMap<String, Register>();

	public List<String> getRegisterNamesRead() {
		ArrayList<String> result = new ArrayList<String>(registerNamesRead);
		Collections.sort(result);
		return result;
	}

	public List<String> getRegisterNamesUpdated() {
		ArrayList<String> result = new ArrayList<String>(registerNamesUpdated);
		Collections.sort(result);
		return result;

	}

	public List<String> getRegisterNamesReadOrUpdated() {
		HashSet<String> both = new HashSet<String>(registerNamesRead);
		both.addAll(registerNamesUpdated);
		ArrayList<String> result = new ArrayList<String>(both);
		Collections.sort(result);
		return result;
	}

	public List<String> getRegisterNames() {
		// make this recursive later and get children???
		List<String> result = new ArrayList<String>();
		for (Map.Entry<Register, SymValueZ3> entry : regvals.entrySet()) {
			Register r = entry.getKey();
			result.add(r.getName());
		}
		return result;
	}

	public void updateRegister(Register r, SymValueZ3 update) {
		try (Context ctx = new Context()) {
			registerNamesUpdated.add(r.getName());
			updateRegisterHelper(ctx, r, update);
			if (!this.knownRegisters.containsKey(r.getName())) {
				this.knownRegisters.put(r.getName(), r);
			}
		}
	}

	private void updateRegisterHelper(Context ctx, Register r, SymValueZ3 update) {
		if (r.isBaseRegister()) {
			regvals.put(r, update);
			return;
		}
		// so, we want to update the base, but also need to keep portions of it.
		// 3 cases, the base might contribute at left, right, or both

		BitVecExpr bv = update.getBitVecExpr(ctx);
		Register base = r.getBaseRegister();
		SymValueZ3 baseVal = this.getRegisterHelper(ctx, base);
		BitVecExpr result = null;
		int lsbInBase = r.getLeastSignificantBitInBaseRegister();
		// consider whether some portion of base remains on the left
		if (r.getBitLength() + lsbInBase < base.getBitLength()) {
			int high = base.getBitLength() - 1;
			int low = r.getBitLength() + lsbInBase;
			BitVecExpr left = ctx.mkExtract(high, low, baseVal.getBitVecExpr(ctx));
			result = ctx.mkConcat(left, bv);
		}
		else {
			result = bv;
		}

		// consider whether some portion of base remains on the right
		if (result.getSortSize() < base.getBitLength()) {
			int high = base.getBitLength() - result.getSortSize() - 1;
			int low = 0;
			BitVecExpr right = ctx.mkExtract(high, low, baseVal.getBitVecExpr(ctx));
			result = ctx.mkConcat(result, right);
		}
		regvals.put(base, new SymValueZ3(ctx, result));
	}

	public SymValueZ3 getRegister(Register r) {
		try (Context ctx = new Context()) {
			this.registerNamesRead.add(r.getName());
			if (!this.knownRegisters.containsKey(r.getName())) {
				this.knownRegisters.put(r.getName(), r);
			}
			return getRegisterHelper(ctx, r);
		}
	}

	// normally a call to get will create a symbolic, but we might
	// want the ability to check if there is a value
	public Boolean hasValueForRegister(Register r) {
		if (r.isBaseRegister()) {
			SymValueZ3 value = regvals.get(r);
			return !(value == null);
		}
		Register base = r.getBaseRegister();
		return this.hasValueForRegister(base);
	}

	private SymValueZ3 getRegisterHelper(Context ctx, Register r) {
		if (r.isBaseRegister()) {
			SymValueZ3 value = regvals.get(r);
			if (value != null) {
				return value;
			}

			if (r.getGroup() != null && r.getGroup().equals("FLAGS")) {
				// we treat flags as special, because we create a single symbolic bit
				BitVecExpr e = ctx.mkBVConst(r.getName(), 1);
				BitVecExpr zeros = ctx.mkBV(0, r.getBitLength() - 1);
				SymValueZ3 di = new SymValueZ3(ctx, ctx.mkConcat(zeros, e));
				this.updateRegisterHelper(ctx, r, di);
				return di;
			}
			BitVecExpr e = ctx.mkBVConst(r.getName(), r.getBitLength());
			SymValueZ3 di = new SymValueZ3(ctx, e);
			this.updateRegisterHelper(ctx, r, di);
			return di;
		}
		int lsbInBase = r.getLeastSignificantBitInBaseRegister();
		Register base = r.getBaseRegister();
		SymValueZ3 baseVal = this.getRegisterHelper(ctx, base);

		BitVecExpr b = ctx.mkExtract(lsbInBase + r.getBitLength() - 1, lsbInBase,
			baseVal.getBitVecExpr(ctx));
		SymValueZ3 result = new SymValueZ3(ctx, b);

		return result;
	}

	public String printableRegister(Context ctx, Register r) {
		Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
		Entry<String, String> valuation = valuationFor(ctx, z3p, r);
		return valuation.getKey() + " = " + valuation.getValue();
	}

	public Entry<String, String> valuationFor(Context ctx, Z3InfixPrinter z3p, Register r) {
		String sizeString = ":" + r.getNumBytes() * 8;

		SymValueZ3 rv = getRegisterHelper(ctx, r);

		if (r.getNumBytes() == 1 && rv.hasBoolExpr()) {
			BoolExpr e = rv.getBoolExpr(ctx);
			e = (BoolExpr) e.simplify();
			return Map.entry(r.toString() + sizeString, z3p.infixTopLevel(e));
		}
		BitVecExpr v = rv.getBitVecExpr(ctx);
		v = (BitVecExpr) v.simplify();
		return Map.entry(r.toString() + sizeString, z3p.infixTopLevel(v));
	}

	public String printableSummary() {
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			StringBuilder result = new StringBuilder();
			result.append("----------------------------------------------------");
			result.append(System.lineSeparator());
			result.append("Registers that were read: ");
			result.append(System.lineSeparator());
			List<String> registersRead = this.getRegisterNamesRead();
			result.append(z3p.fetchListOfStringsHelper(registersRead));

			result.append("Registers that were updated: ");
			result.append(System.lineSeparator());
			List<String> registersUpdated = this.getRegisterNamesUpdated();
			result.append(z3p.fetchListOfStringsHelper(registersUpdated));

			result.append("Registers that were read or updated: ");
			result.append(System.lineSeparator());
			List<String> registersReadOrUpdated = this.getRegisterNamesReadOrUpdated();
			result.append(z3p.fetchListOfStringsHelper(registersReadOrUpdated));

			result.append("Current Valuations (in terms of valuations at start)");
			result.append(System.lineSeparator());

			for (String name : this.getRegisterNamesReadOrUpdated()) {
				Register r = this.knownRegisters.get(name);
				result.append(printableRegister(ctx, r));
				result.append(System.lineSeparator());
			}
			return result.toString();
		}
	}

	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return getRegisterNamesReadOrUpdated().stream().map(n -> {
			Register r = knownRegisters.get(n);
			return valuationFor(ctx, z3p, r);
		});
	}
}
