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
package ghidra.ghidrassist.apple;

import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Detects whether the current {@link Program} is an Apple-flavored binary
 * (Mach-O, Apple Silicon, Objective-C runtime, Swift runtime). GhidrAssist
 * uses this to enrich prompts and to decide when the Apple-specific
 * convenience action is enabled.
 *
 * <p>Nothing in this class decompiles anything new — Ghidra already handles
 * Mach-O / AARCH64 / x86_64 Mach-O binaries natively. This is purely context
 * detection for prompt enrichment and for the one-click analyzer toggle.
 */
public final class AppleBinaryContext {

	private final boolean machO;
	private final boolean appleSilicon;
	private final boolean aarch64;
	private final boolean x86_64;
	private final boolean objectiveC;
	private final boolean swift;
	private final boolean arm64e;
	private final String languageId;

	private AppleBinaryContext(boolean machO, boolean appleSilicon, boolean aarch64,
			boolean x86_64, boolean objectiveC, boolean swift, boolean arm64e,
			String languageId) {
		this.machO = machO;
		this.appleSilicon = appleSilicon;
		this.aarch64 = aarch64;
		this.x86_64 = x86_64;
		this.objectiveC = objectiveC;
		this.swift = swift;
		this.arm64e = arm64e;
		this.languageId = languageId;
	}

	public static AppleBinaryContext from(Program program) {
		if (program == null) {
			return empty();
		}
		String fmt = program.getExecutableFormat();
		String lid = program.getLanguageID() == null ? "" :
			program.getLanguageID().getIdAsString();
		java.util.List<String> blockNames = new java.util.ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			blockNames.add(block.getName() == null ? "" : block.getName());
		}
		return classify(fmt, lid, blockNames, program.getExecutablePath());
	}

	/**
	 * Pure-logic classifier used by {@link #from(Program)}; exposed for tests
	 * so detection can be validated without constructing a {@link Program}.
	 */
	public static AppleBinaryContext classify(String executableFormat, String languageId,
			java.util.List<String> blockNames, String executablePath) {
		boolean machO = MachoLoader.MACH_O_NAME.equals(executableFormat);
		String lid = languageId == null ? "" : languageId;
		boolean appleSilicon = lid.contains(":AppleSilicon");
		boolean aarch64 = lid.startsWith("AARCH64:");
		boolean x86_64 = lid.startsWith("x86:LE:64");

		boolean objc = false;
		boolean swift = false;
		if (blockNames != null) {
			for (String n : blockNames) {
				if (n == null) {
					continue;
				}
				if (n.startsWith("__objc_") || n.equals("__objc") ||
					n.contains("objc_classlist") || n.contains("objc_catlist") ||
					n.contains("objc_selrefs")) {
					objc = true;
				}
				if (n.startsWith("__swift5_") || n.startsWith("__swift_") ||
					n.contains("swift5_types")) {
					swift = true;
				}
			}
		}
		// arm64e is reported through CPU subtype; the SLEIGH variant currently
		// doesn't distinguish it from AppleSilicon, so we fall back to a name hint
		// on the executable path. Pointer-authentication of indirect branches is
		// what matters for the LLM — we just flag that it may be present.
		boolean arm64e = executablePath != null &&
			(executablePath.contains("arm64e") || executablePath.contains("arm64_e"));

		return new AppleBinaryContext(machO, appleSilicon, aarch64, x86_64, objc, swift,
			arm64e, lid);
	}

	private static AppleBinaryContext empty() {
		return new AppleBinaryContext(false, false, false, false, false, false, false, "");
	}

	public boolean isMachO() {
		return machO;
	}

	public boolean isAppleSilicon() {
		return appleSilicon;
	}

	public boolean isAARCH64() {
		return aarch64;
	}

	public boolean isX86_64() {
		return x86_64;
	}

	public boolean hasObjectiveC() {
		return objectiveC;
	}

	public boolean hasSwift() {
		return swift;
	}

	public boolean mayBeArm64e() {
		return arm64e;
	}

	public String languageId() {
		return languageId;
	}

	/**
	 * One-line summary suitable for a status bar or chat system message.
	 */
	public String summary() {
		if (!machO) {
			return "non-Mach-O (" + (languageId.isEmpty() ? "unknown" : languageId) + ")";
		}
		StringBuilder sb = new StringBuilder("Mach-O");
		if (appleSilicon) {
			sb.append(", Apple Silicon");
		}
		else if (aarch64) {
			sb.append(", AArch64");
		}
		else if (x86_64) {
			sb.append(", x86_64");
		}
		if (objectiveC) {
			sb.append(", Objective-C runtime");
		}
		if (swift) {
			sb.append(", Swift runtime");
		}
		if (arm64e) {
			sb.append(", possibly arm64e (PAC)");
		}
		return sb.toString();
	}

	/**
	 * Returns a short block of guidance to prepend to Claude prompts when the
	 * program is Apple-flavored. Empty if nothing Apple-specific was detected.
	 */
	public String promptPreamble() {
		if (!machO && !appleSilicon && !objectiveC && !swift) {
			return "";
		}
		StringBuilder sb = new StringBuilder("Context: this binary is ");
		sb.append(summary()).append(".\n");
		if (objectiveC) {
			sb.append(
				"- Objective-C: calls go through `objc_msgSend` / `_objc_msgSendSuper2`. " +
					"The first argument is `self`, the second is the SEL (as a C string in " +
					"`__objc_methname`). Treat `objc_msgSend(x, sel_foo, a, b)` as `[x foo:a b]`.\n");
		}
		if (swift) {
			sb.append(
				"- Swift: expect mangled names starting with `$s` or `_$s`. Metadata lives in " +
					"`__swift5_types`, `__swift5_proto`, `__swift5_fieldmd`. Error returns use " +
					"a context register, not a C return value.\n");
		}
		if (appleSilicon || arm64e) {
			sb.append(
				"- Apple Silicon ABI (AAPCS64 + Apple's variants): x0..x7 pass args, x8 holds " +
					"the indirect return address for large returns, x16/x17 are scratch used by " +
					"PLT/stub veneers, x18 is reserved on Darwin. ");
			if (arm64e) {
				sb.append("`braa`/`blraa`/`autia` and friends indicate pointer authentication; " +
					"treat them as validated indirect branches/calls.");
			}
			sb.append('\n');
		}
		return sb.toString();
	}
}
