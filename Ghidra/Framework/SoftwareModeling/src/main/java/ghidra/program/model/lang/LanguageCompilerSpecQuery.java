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
package ghidra.program.model.lang;

public class LanguageCompilerSpecQuery {
	public final Processor processor;
	public final Endian endian;
	public final Integer size;
	public final String variant;
	public final CompilerSpecID compilerSpecID;

	/**
	 * Constructs a new LanguageCompilerSpecQuery
	 * 
	 * @param processor the language's processor
	 * @param endian the processor's endianness
	 * @param size the size of an address
	 * @param variant the processor variant
	 * @param compilerSpecID the compiler spec id
	 */
	public LanguageCompilerSpecQuery(Processor processor, Endian endian, Integer size,
			String variant, CompilerSpecID compilerSpecID) {
		this.processor = processor;
		this.endian = endian;
		this.size = size;
		this.variant = variant;
		this.compilerSpecID = compilerSpecID;
	}

	@Override
	public String toString() {
		return "processor=" + processor + "; endian=" + endian + "; size=" + size + "; variant=" +
			variant + "; compiler=" + compilerSpecID;
	}
}
