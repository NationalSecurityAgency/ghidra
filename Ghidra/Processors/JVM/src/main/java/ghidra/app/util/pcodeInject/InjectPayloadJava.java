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
package ghidra.app.util.pcodeInject;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.ClassFileAnalysisState;
import ghidra.javaclass.format.ClassFileJava;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;

/**
 * Subclasses of this class are used to generate p-code to inject for modeling
 * java bytecode in p-code. Each is attached to CALLOTHER p-code op.
 *
 */

public abstract class InjectPayloadJava extends InjectPayloadCallother {
	protected SleighLanguage language;
	protected long uniqueBase;

	public InjectPayloadJava(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName);
		this.language = language;
		this.uniqueBase = uniqBase;
	}

	protected static AbstractConstantPoolInfoJava[] getConstantPool(Program program) {
		ClassFileAnalysisState analysisState;
		try {
			analysisState = ClassFileAnalysisState.getState(program);
		}
		catch (IOException e) {
			return null;
		}
		ClassFileJava classFile = analysisState.getClassFile();
		return classFile.getConstantPool();
	}
}
