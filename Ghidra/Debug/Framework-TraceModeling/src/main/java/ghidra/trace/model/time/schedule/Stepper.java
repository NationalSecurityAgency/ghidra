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
package ghidra.trace.model.time.schedule;

import ghidra.pcode.emu.PcodeThread;

public interface Stepper<T> {
	@SuppressWarnings("rawtypes")
	enum Enum implements Stepper {
		INSTRUCTION {
			@Override
			public void tick(PcodeThread thread) {
				thread.stepInstruction();
			}

			@Override
			public void skip(PcodeThread thread) {
				thread.skipInstruction();
			}
		},
		PCODE {
			@Override
			public void tick(PcodeThread thread) {
				thread.stepPcodeOp();
			}

			@Override
			public void skip(PcodeThread thread) {
				thread.skipPcodeOp();
			}
		};
	}

	@SuppressWarnings("unchecked")
	static <T> Stepper<T> instruction() {
		return Enum.INSTRUCTION;
	}

	@SuppressWarnings("unchecked")
	static <T> Stepper<T> pcode() {
		return Enum.PCODE;
	}

	void tick(PcodeThread<T> thread);

	void skip(PcodeThread<T> thread);
}
