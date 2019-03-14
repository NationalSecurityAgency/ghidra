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

/**
 * 
 * This is a utility class for generating pcode for the lookupswitch operation.
 * 
 * This class is evolving and may eventually be replaced.
 * 
 */

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;

public class SwitchMethods {
	
	static final String KEY = "key";
	static final String SWITCH_TARGET = "switch_target";

	public static String getPcodeForLookupSwitch(InjectContext injectContext, Program program) throws IOException {
		StringBuilder pCode = new StringBuilder();
		
		int defaultAddr = (int) injectContext.inputlist.get(0).getOffset();
		int numPairs = (int) injectContext.inputlist.get(1).getOffset();
		int padding = (int) injectContext.inputlist.get(2).getOffset();
		
		PcodeTextEmitter.emitPopCat1Value(pCode, KEY);

		int target = (int) (injectContext.baseAddr.getOffset() + defaultAddr);
		PcodeTextEmitter.emitAssignConstantToRegister(pCode, SWITCH_TARGET, target);
		ByteProvider provider = new MemoryByteProvider(program.getMemory(),injectContext.baseAddr);
		byte[] bytes = provider.readBytes(1 + padding + 8, 8  * numPairs);
		for (int i = 0, length = bytes.length ; i < length; i += 8){
			int match = ((bytes[i] << 24) & 0xff000000) | ((bytes[i+1] << 16) & 0xff0000) | ((bytes[i+2] <<8) & 0xff00) | (bytes[i+3] & 0xff);
			int offset = ((bytes[i+4] << 24) & 0xff000000) | ((bytes[i+5] << 16) & 0xff0000) | ((bytes[i+6] <<8) & 0xff00) | (bytes[i+7] & 0xff);
			target = (int) (injectContext.baseAddr.getOffset() + offset);
			pCode.append("if (key != " + match +") goto <test"+i+">;\n");
		    pCode.append(SWITCH_TARGET);
			pCode.append(" = inst_start + " +offset+ ";\n");
		    //uncomment this to have the decompiler display multiple switch(address) statements
		    //pCode.append("goto [switch_target];\n");
		    PcodeTextEmitter.emitLabelDefinition(pCode, "test"+i);
		}
		pCode.append("SP=SP;\n");
		provider.close();
		return pCode.toString();
	}
}

