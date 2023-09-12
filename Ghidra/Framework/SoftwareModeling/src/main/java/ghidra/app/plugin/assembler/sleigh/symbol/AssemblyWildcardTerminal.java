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
package ghidra.app.plugin.assembler.sleigh.symbol;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyOperandData;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;

/**
 * A terminal that accepts a wildcard.
 * <p>
 * This Terminal wraps another "internal" AssemblyTerminal and always ensures
 * that we claim that our input (which is being parsed) matches the internal
 * AssemblyTerminal.
 * <p>
 * We do this by adding a matchAll method to AssemblyTerminal and calling this
 * when AssemblyWildcardTerminal.match is called.
 */
public class AssemblyWildcardTerminal extends AssemblyTerminal {
	protected final AssemblyTerminal internal;
	protected final AssemblyOperandData meta;
	protected final Address anticipatedAddress;

	/**
	 * Construct a terminal that accepts only the given string.
	 */
	public AssemblyWildcardTerminal(AssemblyTerminal internal, String wildcardName, int id,
			Address anticipatedAddress) {
		super("WILD-" + wildcardName + ":" + internal.getName());
		this.internal = internal;
		int type;
		// TODO: Are there other variants we should handle here?
		if (internal instanceof AssemblyNumericTerminal) {
			type = OperandType.SCALAR;
		} else {
			type = OperandType.REGISTER;
		}
		this.meta = new AssemblyOperandData(wildcardName, id, type);
		this.anticipatedAddress = anticipatedAddress;
	}

	@Override
	public String toString() {
		return "WILD-" + meta.getWildcardName() + ":" + internal.toString();
	}

	@Override
	public Collection<? extends AssemblyParseToken> match(String buffer, int pos, AssemblyGrammar grammar,
			AssemblyNumericSymbols labels) {
		Collection<? extends AssemblyParseToken> internalResults;
		if (internal instanceof AssemblyNumericTerminal) {
			internalResults = ((AssemblyNumericTerminal) internal).matchAllWithAddress(grammar,
					labels, this.anticipatedAddress);
		} else {
			internalResults = internal.matchAll(grammar, labels);
		}
		for (AssemblyParseToken t : internalResults) {
			t.setOperandData(meta);
		}
		return internalResults;
	}

	@Override
	public Collection<? extends AssemblyParseToken> matchAll(AssemblyGrammar grammar, AssemblyNumericSymbols labels) {
		Collection<? extends AssemblyParseToken> internalResults;
		if (internal instanceof AssemblyNumericTerminal) {
			internalResults = ((AssemblyNumericTerminal) internal).matchAllWithAddress(grammar,
					labels, this.anticipatedAddress);
		} else {
			internalResults = internal.matchAll(grammar, labels);
		}
		for (AssemblyParseToken t : internalResults) {
			t.setOperandData(meta);
		}
		return internalResults;
	}

	public AssemblyTerminal getInternal() {
		return internal;
	}

	@Override
	public Collection<String> getSuggestions(String got, AssemblyNumericSymbols labels) {
		return internal.getSuggestions(got, labels);
	}

	@Override
	public boolean takesOperandIndex() {
		return internal.takesOperandIndex();
	}
}
