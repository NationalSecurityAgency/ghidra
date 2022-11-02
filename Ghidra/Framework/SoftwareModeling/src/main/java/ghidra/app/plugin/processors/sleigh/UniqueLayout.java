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
package ghidra.app.plugin.processors.sleigh;

/**
 * Offsets for various ranges in the p-code unique space.  Offsets are either:
 *    1) Relative to the last temporary allocated statically by the SLEIGH compiler
 *        or a particular language (.sla), OR
 *    2) Absolute within the unique address space.
 * So the layout of the unique address space looks like:
 *    1)  SLEIGH static temporaries
 *    2)  Runtime temporaries used by the SLEIGH p-code generator
 *    3)  Temporaries used by the PcodeInjectLibrary for p-code snippets
 *    4)  Temporaries generated during (decompiler) analysis
 *
 *    The "unique" space is set to 32 bits across all architectures.
 *    The maximum offset is 0xFFFFFFFF.
 *    The offsets and names should match with the parallel decompiler enum in translate.hh
 */
public enum UniqueLayout {
	SLEIGH_BASE(0, true),				// First offset after SLEIGH static temporaries
	RUNTIME_BOOLEAN_INVERT(0, true),
	RUNTIME_RETURN_LOCATION(0x80, true),
	RUNTIME_BITRANGE_EA(0x100, true),
	INJECT(0x200, true),
	ANALYSIS(0x10000000, false);

	private final long offset;
	private final boolean isRelative;		// Is this offset relative to the end of SLEIGH statics

	UniqueLayout(long off, boolean isRel) {
		offset = off;
		isRelative = isRel;
	}

	/**
	 * Get the starting offset of a named range in the unique address space.  The returned offset
	 * is absolute and specific to the given SLEIGH language.
	 * @param language is the given SLEIGH language
	 * @return the absolute offset
	 */
	public long getOffset(SleighLanguage language) {
		return (isRelative && language != null) ? language.getUniqueBase() + offset : offset;
	}
}
