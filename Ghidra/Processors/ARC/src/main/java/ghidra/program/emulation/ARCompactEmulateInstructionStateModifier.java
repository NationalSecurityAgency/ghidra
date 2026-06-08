package ghidra.program.emulation;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.program.model.pcode.Varnode;

public class ARCompactEmulateInstructionStateModifier extends EmulateInstructionStateModifier {

	public ARCompactEmulateInstructionStateModifier(Emulate emu) {
		super(emu);

		registerPcodeOpBehavior("norm", new ARCompactNormOpBehavior());
	}

	/**
	 * Implements ARCompact's norm instruction.
	 *
	 * It is defined by:
	 *   Computes the normalization integer for the signed value in the
	 *   operand. The normalization integer is the amount by which the
	 *   operand must be shifted left to normalize the operand as a
	 *   32-bit signed integer.
	 *
	 * An other way to understand this operation is to use some rules:
	 * * norm(0) = 31
	 * * if x s> 0, norm(x) = clz(x) - 1, with clz being "count leading zeros"
	 * * if x s< 0, norm(x) = norm(~x)
	 */
	private class ARCompactNormOpBehavior implements OpBehaviorOther {
		@Override
		public void evaluate(Emulate emu, Varnode out, Varnode[] inputs) {
			if (out == null) {
				throw new LowlevelError("CALLOTHER: Norm op missing required output");
			}

			if (inputs.length != 2 || inputs[1].getSize() == 0 || inputs[1].isConstant()) {
				throw new LowlevelError(
					"CALLOTHER: Norm op requires one non-constant varnode input");
			}

			Varnode in = inputs[1];
			if (in.getSize() != 4 ) {
				throw new LowlevelError(
					"CALLOTHER: Norm op only supports varnodes of size 4 bytes");
			}

			MemoryState memoryState = emu.getMemoryState();
			long value = memoryState.getValue(in);
			long mask = 1L << ((in.getSize() * 8) - 1);
			if ((mask & value) != 0) {
				value = ~value;
			}
			mask >>>= 1;
			long count = 0;
			while (mask != 0) {
				if ((mask & value) != 0) {
					break;
				}
				++count;
				mask >>>= 1;
			}
			memoryState.setValue(out, count);
		}
	}
}
