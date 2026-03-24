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

import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

@UseropLibrary("arm")
public class ArmPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new ArmPcodeUseropLibrary<>(language);
	}

	public static class ArmPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final RegisterValue tMode;
		private final RegisterValue aMode;

		// LATER: This should probably be injected
		private final ArmCpuState cpuState = new ArmCpuState();

		public ArmPcodeUseropLibrary(SleighLanguage language) {
			Register tModeReg = language.getRegister("TMode");
			if (tModeReg != null) {
				tMode = new RegisterValue(tModeReg, BigInteger.ONE);
				aMode = new RegisterValue(tModeReg, BigInteger.ZERO);
			}
			else {
				tMode = null;
				aMode = null;
			}

			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

			putOp(factory.define("VectorSignedToFloat")
					.params("s", "mode")
					.body(args -> switch (args.get(0).getSize()) {
						case 4 -> "__op_output = int2float(s);";
						default -> throw new LowlevelError(
							"VectorSignedToFloat: invalid dest size of " + args.get(0).getSize());
					})
					.build());
			putOp(factory.define("VectorUnsignedToFloat")
					.params("s", "mode")
					.body(args -> switch (args.get(0).getSize()) {
						case 4 -> {
							Varnode s = args.get(1);
							yield """
									temp:%d = zext(s);
									__op_output = int2float(s);
									""".formatted(s.getSize() + 1);
						}
						default -> throw new LowlevelError(
							"VectorSignedToFloat: invalid dest size of " + args.get(0).getSize());
					})
					.build());
		}

		@PcodeUserop(modifiesContext = true)
		public void setISAMode(@OpExecutor PcodeExecutor<T> exec, boolean tb) {
			if (!(exec instanceof PcodeThreadExecutor<T> tExec)) {
				return;
			}
			tExec.getThread().overrideContext(tb ? tMode : aMode);
		}

		@PcodeUserop(functional = true)
		public void disableIRQinterrupts() {
			cpuState.setIrqEnabled(false);
		}

		@PcodeUserop(functional = true)
		public void enableIRQinterrupts() {
			cpuState.setIrqEnabled(true);
		}

		@PcodeUserop(functional = true, hasSideEffects = false)
		public boolean isCurrentModePrivileged() {
			return cpuState.isPrivileged();
		}

		@PcodeUserop(functional = true)
		public void setMainStackPointer(long mainStackPointer) {
			cpuState.setMainStackPointer(mainStackPointer);
		}

		@PcodeUserop(functional = true)
		public void setProcessStackPointer(long processStackPointer) {
			cpuState.setProcessStackPointer(processStackPointer);
		}

		@PcodeUserop(functional = true, hasSideEffects = false)
		public long getProcessStackPointer() {
			return cpuState.getProcessStackPointer();
		}

		@PcodeUserop(functional = true/*Maybe not*/)
		public void DataSynchronizationBarrier(int todo) {
			Msg.warn(this, "TODO:DataSyncBarrier");
		}

		@PcodeUserop(functional = true/*Maybe not*/)
		public void InstructionSynchronizationBarrier(int todo) {
			Msg.warn(this, "TODO:InsSyncBarrier");
		}

		@PcodeUserop(functional = true)
		public void setThreadModePrivileged(boolean privileged) {
			cpuState.setThreadModePrivileged(privileged);
		}

		@PcodeUserop(functional = true, hasSideEffects = false)
		public boolean isThreadMode() {
			return cpuState.isThreadMode();
		}

		@PcodeUserop(functional = true)
		public void setBasePriority(long basePriority) {
			cpuState.setBasePriority(basePriority);
		}
	}
}
