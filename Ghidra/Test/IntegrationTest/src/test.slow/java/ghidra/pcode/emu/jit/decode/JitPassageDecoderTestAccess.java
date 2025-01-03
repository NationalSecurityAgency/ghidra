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
package ghidra.pcode.emu.jit.decode;

import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.exec.PcodeProgram;

public class JitPassageDecoderTestAccess {

	public static JitPassage simulateFromPcode(PcodeProgram program, JitPcodeThread thread) {
		JitPassageDecoder decoder = new JitPassageDecoder(thread);
		DecoderForOnePassage d4passage = new DecoderForOnePassage(decoder, AddrCtx.NOWHERE, 0);
		d4passage.externalBranches.clear();
		DecoderForOneStride d4stride = new DecoderForOneStride(decoder, d4passage, AddrCtx.NOWHERE);
		DecoderExecutor exec = new DecoderExecutor(d4stride, AddrCtx.NOWHERE);
		d4passage.firstOps.put(AddrCtx.NOWHERE, exec.rewrite(program.getCode().getFirst()));

		exec.execute(program);
		exec.checkFallthroughAndAccumulate(program);
		d4passage.strides.add(d4stride.toStride());

		return d4passage.finish();
	}
}
