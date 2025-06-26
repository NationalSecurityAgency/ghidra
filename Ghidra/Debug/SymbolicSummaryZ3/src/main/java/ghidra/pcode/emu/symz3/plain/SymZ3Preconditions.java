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
package ghidra.pcode.emu.symz3.plain;

import java.util.*;
import java.util.stream.Stream;

import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.symz3.model.SymValueZ3;

/**
 * Store not related to a specific space for the Symbolic Summary Z3
 * 
 * <p>
 * This information is available to any {@link SymZ3Space} and is shared across them
 */
public class SymZ3Preconditions {
	private final List<String> preconditions = new ArrayList<>();

	public void addPrecondition(String r) {
		preconditions.add(r);
	}

	public String printableSummary() {
		StringBuilder result = new StringBuilder();
		if (preconditions.isEmpty()) {
			result.append("NO PRECONDITIONS");
			result.append(System.lineSeparator());
			return result.toString();
		}
		result.append("PRECONDITIONS:");
		result.append(System.lineSeparator());
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			for (String b : preconditions) {
				BoolExpr be = SymValueZ3.deserializeBoolExpr(ctx, b);
				be = (BoolExpr) be.simplify();
				result.append("" + z3p.infix(be));
				result.append(System.lineSeparator());
			}
		}
		return result.toString();
	}

	public List<String> getPreconditions() {
		return Collections.unmodifiableList(preconditions);
	}

	public Stream<String> streamPreconditions(Context ctx, Z3InfixPrinter z3p) {
		return preconditions.stream().map(b -> {
			BoolExpr be = SymValueZ3.deserializeBoolExpr(ctx, b);
			return z3p.infix(be.simplify());
		});
	}

	public void clear() {
		preconditions.clear();
	}
}
