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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;

@UseropLibrary("arcompact")
public class ARCompactPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new ARCompactPcodeUseropLibrary<>(language);
	}

	public static class ARCompactPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		public ARCompactPcodeUseropLibrary(SleighLanguage language) {
			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

            // Normalization of signed 32-bit integers:
            // * norm(0) = 31
            // * if x s> 0, norm(x) = clz(x) - 1, with clz being "count leading zeros"
            // * if x s< 0, norm(x) = norm(~x)
			putOp(factory.define("norm").params("value").body(args -> """
                    local abs_value:4 = value;
                    if (value s>= 0:4) goto <nonnegative_value>;
                    abs_value = ~value;
                    <nonnegative_value>
                    __op_output = lzcount(abs_value) - 1:4;
					""").build());
		}
	}
}
