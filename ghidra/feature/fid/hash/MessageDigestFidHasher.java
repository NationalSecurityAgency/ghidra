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
package ghidra.feature.fid.hash;

import java.util.*;

import generic.hash.MessageDigest;
import generic.hash.MessageDigestFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.search.InstructionSkipper;

/**
 * Given a FunctionExtentGenerator and a MonitoredMessageDigest, will combine
 * both to become a FidHasher.
 *
 */
public class MessageDigestFidHasher implements FidHasher {
	private static final int BUFFER_SIZE = 110000;

	protected final byte shortCodeUnitLimit;
	protected final FunctionExtentGenerator generator;
	protected final MessageDigest fullDigest;
	protected final MessageDigest specificDigest;
	protected final byte[] buffer;
	protected final Collection<InstructionSkipper> skippers;

	public MessageDigestFidHasher(FunctionExtentGenerator generator, byte shortCodeUnitLimit,
			MessageDigestFactory digestFactory, Collection<InstructionSkipper> skippers) {
		this.shortCodeUnitLimit = shortCodeUnitLimit;
		this.generator = generator;
		this.fullDigest = digestFactory.createDigest();
		this.specificDigest = digestFactory.createDigest();
		this.skippers = skippers;
		buffer = new byte[BUFFER_SIZE];
	}

	private static boolean hasRelocation(Mask mask,Address minAddress,Address maxAddress,RelocationTable relocationTable) {
		byte[] bytes = mask.getBytes();
		for (byte b : bytes) {
			if (b != 0) {
				break;
			}
			minAddress = minAddress.addWrap(1);
		}
		for (int jj = bytes.length - 1; jj >= 0; --jj) {
			if (bytes[jj] != 0) {
				break;
			}
			maxAddress = maxAddress.subtract(1);
		}
		if (minAddress.compareTo(maxAddress) <= 0) {
			AddressSet range = new AddressSet(minAddress, maxAddress);
			Iterator<Relocation> relocations = relocationTable.getRelocations(range);
			if (relocations.hasNext()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public FidHashQuad hash(Function func) throws MemoryAccessException {

		List<CodeUnit> extent = generator.calculateExtent(func);
		if (extent.size() < shortCodeUnitLimit) {
			return null;						// Not enough code units
		}
		Program program = func.getProgram();
		Memory memory = program.getMemory();
		RelocationTable relocationTable = program.getRelocationTable();

		fullDigest.reset();
		specificDigest.reset();

		int specificCount = 0;
		int callCount = 0;
		int codeUnitIndex = -1;
		Iterator<CodeUnit> codeUnitIterator = extent.iterator();
		CodeUnit codeUnit = null;

		while (codeUnitIterator.hasNext()) {
			codeUnit = codeUnitIterator.next();
			++codeUnitIndex;
			if (codeUnitIndex >= Short.MAX_VALUE - 1) {
				break;
			}
			Address minAddress = codeUnit.getMinAddress();
			Address maxAddress = codeUnit.getMaxAddress();
			int amountToFetch = codeUnit.getLength();
			int actualNumberRead = memory.getBytes(minAddress, buffer, 0, amountToFetch);
			if (codeUnit instanceof Instruction) {
				Instruction instruction = (Instruction) codeUnit;
				boolean skip = false;
				for (InstructionSkipper skipper : skippers) {
					if (skipper.shouldSkip(buffer,amountToFetch)) {
						skip = true;
						codeUnitIndex -= 1;			// Don't count this in the score
						break;
					}
				}
				if (skip) {
					continue;
				}

				if (instruction.getFlowType().isCall()) {
					callCount += 1;
				}
				// this block updates the specific hash with all the operand scalars
				// in the instruction (whereas the full hash has masked all the operands
				// out from the instruction opcodes)
				InstructionPrototype prototype = instruction.getPrototype();
				Mask instructMask = prototype.getInstructionMask();
				for (int ii = 0; ii < instruction.getNumOperands(); ++ii) {
					Mask operandMask = prototype.getOperandValueMask(ii);
					if (operandMask == null) {
						continue;
					}
					Object[] opObjects = instruction.getOpObjects(ii);
					int specificUpdate = (ii + 1) * 7777;	// Order independent subhash (into specificDigest) for 1 operand
					int fullUpdate = specificUpdate; // Order independent subhash (into fullDigest) for 1 operand
					for (Object obj : opObjects) {
						if (obj instanceof Scalar) {
							int operandType = instruction.getOperandType(ii);
							Scalar scalar = (Scalar)obj;
							long val = scalar.getSignedValue();
							if (hasRelocation(operandMask,minAddress,maxAddress,relocationTable)) {
								// If we know scalar is part of an address, do not include
								val = 0xfeeddead;		// Placeholder hash, meaning scalar present but not used
							}
							else if (OperandType.isScalar(operandType)) {	// If whole operand is the scalar
								if (OperandType.isAddress(operandType)) {	// Make sure its not an address
									val = 0xfeeddead;	// Scalar is present but value not used in hash
								}
								else {
									specificCount += 1;	// Count the fact that value is used in hash
								}
							}
							else {										// If not the whole operand
								if ((val >= 256) || (val <= -256)) {	// Make sure scalar is small
									val = 0xfeeddead;	// Scalar is present but value not used in hash
								}
								else {
									specificCount += 1;	// Count the fact that value is used in hash
								}
							}
							// Mix scalar value to get more bit diversity, add in in a commutative way
							specificUpdate = specificUpdate + ((int) val + 1234567) * 67999;
							fullUpdate += 0xfeeddead;				// Scalar value is never used in full hash, indicate scalar was present
						}
						else if (obj instanceof Register) {			// Registers get thrown in to all 3 hashes
							Register reg = (Register)obj;
							int val = reg.getOffset();		// Use offset in register space in hash
							val = (val + 7654321) * 98777;	// Different mixing function to distinguish from scalar
							fullUpdate += val;
							specificUpdate += val;
						}
						else if (obj instanceof Address) {
							// Hash in placeholder value for address scalar (value is not used)
							specificUpdate = specificUpdate + (0xfeeddead + 1234567) * 67999;
							fullUpdate += 0xfeeddead;
						}
					}
					fullDigest.update(fullUpdate);
					specificDigest.update(specificUpdate);
				}
				try {
					instructMask.applyMask(buffer, 0, buffer, 0);
				}
				catch (NullPointerException e) {
					// something really bad happened with the instruction prototype not being
					// able to tell what the mask is; make the entire code unit constant because it
					// cannot give us reliable information
					for (int ii = 0; ii < actualNumberRead; ++ii) {
						buffer[ii] = (byte) 0xa5;
					}
				}
				catch (IncompatibleMaskException e) {
					throw new RuntimeException(
						"Internal error - mask exception implies buffer too small", e);
				}
			}
			fullDigest.update(buffer, 0, actualNumberRead);
			specificDigest.update(buffer, 0, actualNumberRead);
		}

		// codeUnitIndex is now a length, not the index of the last element
		++codeUnitIndex;

		if (codeUnitIndex < shortCodeUnitLimit) {
			return null;
		}

		short fullCount = (short) (codeUnitIndex - callCount);
		byte additionalSpecificCount = (byte) Math.min(specificCount, Byte.MAX_VALUE);

		return new FidHashQuadImpl(fullCount, fullDigest.digestLong(),
				additionalSpecificCount, specificDigest.digestLong());
	}
}
