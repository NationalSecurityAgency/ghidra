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
package ghidra.app.util.importer;

import java.util.List;

import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

public class LcsHintLoadSpecChooser implements LoadSpecChooser {
	private final LanguageID languageID;
	private final CompilerSpecID compilerSpecID;

	public LcsHintLoadSpecChooser(Language language, CompilerSpec compilerSpec) {
		this.languageID = language.getLanguageID();
		this.compilerSpecID = compilerSpec == null ? null : compilerSpec.getCompilerSpecID();
	}

	@Override
	public LoadSpec choose(List<LoadSpec> loadSpecs) {
		for (LoadSpec loadSpec : loadSpecs) {
			if (loadSpec == null) {
				Msg.warn(this, "found null load spec whilst trying to choose");
			}
			else if (loadSpec.isPreferred()) {
				LanguageCompilerSpecPair lcsPair = loadSpec.getLanguageCompilerSpec();
				if (lcsPair == null) {
					Msg.warn(this, "load spec " + loadSpec +
						" proffered null LCS pair whilst trying to choose");
				}
				else {
					if (lcsPair.languageID.equals(languageID) &&
						(compilerSpecID == null || lcsPair.compilerSpecID.equals(compilerSpecID))) {
						return loadSpec;
					}
				}
			}
		}
		for (LoadSpec loadSpec : loadSpecs) {
			if (loadSpec == null) {
				Msg.warn(this, "found null load spec whilst trying to choose");
			}
			else {
				LanguageCompilerSpecPair lcsPair = loadSpec.getLanguageCompilerSpec();
				if (lcsPair == null) {
					Msg.warn(this, "load spec " + loadSpec +
						" proffered null LCS pair whilst trying to choose");
				}
				else {
					if (lcsPair.languageID.equals(languageID) &&
						(compilerSpecID == null || lcsPair.compilerSpecID.equals(compilerSpecID))) {
						return loadSpec;
					}
				}
			}
		}
		return null;
	}

	@Override
	public boolean usePreferred() {
		return false;
	}
}
