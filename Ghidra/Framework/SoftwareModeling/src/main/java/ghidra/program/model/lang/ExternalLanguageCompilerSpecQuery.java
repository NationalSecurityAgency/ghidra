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

/**
 * Analog to LanguageCompilerSpecQuery, for use with querying External Languages.
 * That is, languages that exist in other products, like IDA-Pro's 'metapc.'
 */
public class ExternalLanguageCompilerSpecQuery {
	public final String externalProcessorName;
	public final String externalTool;
	public final Endian endian;
	public final Integer size;
	public final CompilerSpecID compilerSpecID;

	public ExternalLanguageCompilerSpecQuery(String externalProcessorName, String externalTool,
			Endian endian, Integer size, CompilerSpecID compilerSpecID) {
		this.externalProcessorName = externalProcessorName;
		this.externalTool = externalTool;
		this.endian = endian;
		this.size = size;
		this.compilerSpecID = compilerSpecID;
	}

	@Override
	public String toString() {
		return "externalProcessorName=" + externalProcessorName + "; externalTool=" + externalTool +
			"; endian=" + endian + "; size=" + size + "; compiler=" + compilerSpecID;
	}
}
