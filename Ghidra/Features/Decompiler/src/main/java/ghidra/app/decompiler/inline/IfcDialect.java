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
package ghidra.app.decompiler.inline;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Per-processor configuration for {@link IfcPcodeEmitter}: the
 * mnemonics and registers that carry IFC-style "inline function call"
 * semantics.  Lets the same emitter and dispatcher implementations
 * serve multiple architectures with IFC-style semantics that differ
 * only in naming.
 *
 * <p>Mnemonic sets are compared case-insensitively after lower-casing
 * the instruction's mnemonic; pass mnemonics in any case.
 */
public final class IfcDialect {

	private final Set<String> ifretMnemonics;
	private final Set<String> ifcallMnemonics;
	private final Set<String> ex9DispatchMnemonics;
	private final Set<String> passiveTerminalMnemonics;
	private final String ifcOnRegisterName;
	private final String ifcLpRegisterName;
	private final int maxBodyInsns;

	private IfcDialect(Builder b) {
		this.ifretMnemonics = Set.copyOf(b.ifret);
		this.ifcallMnemonics = Set.copyOf(b.ifcall);
		this.ex9DispatchMnemonics = Set.copyOf(b.ex9);
		this.passiveTerminalMnemonics = Set.copyOf(b.passiveTerm);
		this.ifcOnRegisterName = b.ifcOnRegisterName;
		this.ifcLpRegisterName = b.ifcLpRegisterName;
		this.maxBodyInsns = b.maxBodyInsns;
	}

	/** Mnemonics that mark a body's ifret-style terminator. */
	public Set<String> getIfretMnemonics() {
		return ifretMnemonics;
	}

	/** Mnemonics that mark an ifcall-style call/transition. */
	public Set<String> getIfcallMnemonics() {
		return ifcallMnemonics;
	}

	/**
	 * Mnemonics for the "execute-immediate from table" dispatch
	 * (e.g. NDS32 {@code ex9.it}).  An instance may resolve to either
	 * a CALL or a JUMP via its attached reference, and the emitter
	 * handles both shapes.  Empty if the dialect has no such mechanism.
	 */
	public Set<String> getEx9DispatchMnemonics() {
		return ex9DispatchMnemonics;
	}

	/**
	 * Bare-terminal mnemonics inside an IFC body that exit the
	 * enclosing function rather than ifret back to the ifcall
	 * caller_next (e.g. NDS32 {@code pop25}, {@code ret}, {@code jr}).
	 */
	public Set<String> getPassiveTerminalMnemonics() {
		return passiveTerminalMnemonics;
	}

	/** Name of the boolean register tracking IFC mode (1 = in IFC mode). */
	public String getIfcOnRegisterName() {
		return ifcOnRegisterName;
	}

	/** Name of the link register storing the IFC return address. */
	public String getIfcLpRegisterName() {
		return ifcLpRegisterName;
	}

	/**
	 * Largest body (in instructions) eligible for inline emission.  At
	 * the limit the inlined pcode would inflate the synthetic stream
	 * disproportionately to the rendering benefit, so the analyzer
	 * leaves these bodies on the dispatch path instead.
	 */
	public int getMaxBodyInsns() {
		return maxBodyInsns;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		private final Set<String> ifret = new LinkedHashSet<>();
		private final Set<String> ifcall = new LinkedHashSet<>();
		private final Set<String> ex9 = new LinkedHashSet<>();
		private final Set<String> passiveTerm = new LinkedHashSet<>();
		private String ifcOnRegisterName;
		private String ifcLpRegisterName;
		private int maxBodyInsns = 600;

		private Builder() {
		}

		public Builder ifretMnemonics(String... mnemonics) {
			lowerAll(mnemonics, ifret);
			return this;
		}

		public Builder ifcallMnemonics(String... mnemonics) {
			lowerAll(mnemonics, ifcall);
			return this;
		}

		public Builder ex9DispatchMnemonics(String... mnemonics) {
			lowerAll(mnemonics, ex9);
			return this;
		}

		public Builder passiveTerminalMnemonics(String... mnemonics) {
			lowerAll(mnemonics, passiveTerm);
			return this;
		}

		public Builder ifcOnRegister(String name) {
			this.ifcOnRegisterName = name;
			return this;
		}

		public Builder ifcLpRegister(String name) {
			this.ifcLpRegisterName = name;
			return this;
		}

		public Builder maxBodyInsns(int n) {
			this.maxBodyInsns = n;
			return this;
		}

		public IfcDialect build() {
			if (ifcOnRegisterName == null || ifcLpRegisterName == null) {
				throw new IllegalStateException(
					"IfcDialect requires both IFC-on and ifc-lp register names");
			}
			return new IfcDialect(this);
		}

		private static void lowerAll(String[] src, Set<String> dst) {
			Arrays.stream(src).map(String::toLowerCase).forEach(dst::add);
		}
	}
}
