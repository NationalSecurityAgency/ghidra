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
package ghidra.program.emulation;

import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.BuilderStage1;
import ghidra.program.model.lang.InjectPayloadSegment;
import ghidra.program.model.lang.InjectPayloadSleigh;

@UseropLibrary(id = "x86")
public class X86PcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		if (hasSegmentop(language)) {
			// SegmentopPcodeUseropLibraryFactory provides segment from the pspec
			return new X86PcodeUseropLibrary<>();
		}
		return new X86FlatPcodeUseropLibrary<>();
	}

	static boolean hasSegmentop(SleighLanguage language) {
		List<InjectPayloadSleigh> injects = language.getAdditionalInject();
		return injects != null && injects.stream().anyMatch(InjectPayloadSegment.class::isInstance);
	}

	public static class X86PcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {

		/**
		 * LATER: For petri-dish emulation, this is perfect. However, for multi-threaded and
		 * systems-level stuff, we'll probably need an actual mutex of some sort. We'll also want to
		 * make sure the behavior is accurate in the face of errors and interrupts.
		 */
		@PcodeUserop(functional = true)
		public void LOCK() {
		}

		@PcodeUserop(functional = true)
		public void UNLOCK() {
		}
	}

	/**
	 * The x86 library for the 32- and 64-bit languages, which declare no {@code segmentop}
	 * 
	 * <p>
	 * Instructions with 16-bit operand or address size still call {@code segment}. These languages
	 * model a flat address space, so {@code segment} ignores the segment register and zero-extends
	 * the offset.
	 */
	public static class X86FlatPcodeUseropLibrary<T> extends X86PcodeUseropLibrary<T> {
		@PcodeUserop
		public SleighPcodeUseropDefinition segment(BuilderStage1 builder) {
			return builder.params("base", "inner").body(_ -> """
					__op_output = zext(inner);
					""").build();
		}
	}
}
