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

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Program;

/**
 * Subclasses of this class are used to generate pcode to inject for modeling
 * java bytecode in pcode.
 *
 */

public abstract class InjectPayloadJava implements InjectPayload {
	protected SleighLanguage language;
	protected long uniqueBase;
	private String sourceName;

	public InjectPayloadJava(String sourceName, SleighLanguage language, long uniqBase) {
		this.language = language;
		this.sourceName = sourceName;
		this.uniqueBase = uniqBase;
	}

	protected static AbstractConstantPoolInfoJava[] getConstantPool(Program program) {
		ConstantPoolJava cPool = null;
		try {
			cPool = new ConstantPoolJava(program);
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cPool.getConstantPool();
	}

	@Override
	public int getType() {
		return InjectPayload.CALLOTHERFIXUP_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// Not used
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public InjectParameter[] getInput() {
		return null;
	}

	@Override
	public InjectParameter[] getOutput() {
		return null;
	}
}
