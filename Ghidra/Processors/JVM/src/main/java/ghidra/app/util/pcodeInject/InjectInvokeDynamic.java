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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class InjectInvokeDynamic extends InjectPayloadJava {

	public InjectInvokeDynamic(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		AbstractConstantPoolInfoJava[] constantPool = getConstantPool(program);
		int constantPoolIndex = (int) con.inputlist.get(0).getOffset();
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, uniqueBase);
		InvokeMethods.getPcodeForInvokeDynamic(pCode, constantPoolIndex, constantPool);
		return pCode.getPcodeOps();
	}
}
