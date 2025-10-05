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
package ghidra.app.plugin.core.analysis;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that detects MIPS functions that return function pointers.
 *
 * Pattern detected:
 *   jal     some_function
 *   nop
 *   jalr    $v0              # $v0 used immediately for indirect call
 *
 * This indicates that some_function returns a function pointer in $v0.
 * The analyzer automatically updates the function signature to reflect this.
 */
public class MipsFunctionSignatureAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "MIPS Function Signature Analyzer";
	private static final String DESCRIPTION =
		"Detects MIPS functions that return function pointers by analyzing " +
		"patterns where return values are immediately used in indirect calls.";

	// Track how many times each function's return value is used in jalr/jr
	private Map<Function, Integer> functionPointerReturners = new HashMap<>();

	public MipsFunctionSignatureAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after basic analysis but before function pointer analyzer
		// This ensures instructions are analyzed but we fix signatures before resolving pointers
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		// Enable: This target uses a jal -> jalr $v0 pattern where a function returns
		// a function pointer that is immediately called via jalr $v0.
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("MIPS"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Msg.info(this, "Analyzing MIPS function signatures for function pointer returns...");

		functionPointerReturners.clear();
		int patternsFound = 0;
		int signaturesFixed = 0;

		// Phase 1: Scan for pattern (jal followed by jalr $v0)
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		int totalInstructions = 0;
		int jalrCount = 0;
		int v0Count = 0;
		int v1Count = 0;
		int unknownTargetCount = 0;

		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instructions.next();
			totalInstructions++;

			String mnemonic = instr.getMnemonicString();

			// Look for jalr or jr instructions
			if (mnemonic.equals("jalr") || mnemonic.equals("_jalr") ||
			    mnemonic.equals("jr") || mnemonic.equals("_jr")) {

				jalrCount++;

				// Determine the jump target register robustly from operands (prefer non-$ra register)
				Register targetReg = getJumpTargetRegister(instr);
				Register dbgR0 = instr.getRegister(0);
				Register dbgR1 = instr.getRegister(1);
				if (targetReg == null) {
					// Fallback: try direct register slots if operand objects were empty
					Register r0 = dbgR0;
					Register r1 = dbgR1;
					if (r1 != null && !"ra".equals(r1.getName())) targetReg = r1;
					else if (r0 != null && !"ra".equals(r0.getName())) targetReg = r0;
					else if (r1 != null) targetReg = r1;
					else if (r0 != null) targetReg = r0;
				}

				// Debug: log first few jalr/jr target decoding attempts
				if (jalrCount <= 10) {
					String t = (targetReg == null ? "null" : targetReg.getName());
					String s0 = (dbgR0 == null ? "null" : dbgR0.getName());
					String s1 = (dbgR1 == null ? "null" : dbgR1.getName());
					Msg.info(this, "Decode jalr/jr at " + instr.getAddress() + ": targetReg=" + t + ", r0=" + s0 + ", r1=" + s1);
				}

				// Skip jr/jalr when the jump target is $ra (function returns)
				if (targetReg != null && targetReg.getName().equals("ra")) {
					continue;
				}

				if (targetReg == null) {
					unknownTargetCount++;
					if (unknownTargetCount <= 3) {

					// NOTE: continue below will skip classification debug; this extra block logs basics

						Msg.debug(this, "Skipping jalr/jr at " + instr.getAddress() + ": could not extract target register");

					// Extra debug for first few sites
					if (jalrCount <= 10) {
						Msg.info(this, "Site " + jalrCount + ": mnemonic=" + mnemonic +
							", addr=" + instr.getAddress());
					}

					}
					continue;
				}


					// Debug: candidate site classification
					if ("v0".equals(targetReg.getName()) || "v1".equals(targetReg.getName())) {
						Msg.info(this, "Candidate return-value jalr/jr at " + instr.getAddress() + " using $" + targetReg.getName());
					}

				// Check if target register is $v0 or $v1 (return value registers)
				if ("v0".equals(targetReg.getName()) || "v1".equals(targetReg.getName())) {
					if ("v0".equals(targetReg.getName())) {
						v0Count++;
						if (v0Count <= 3) {
							Msg.info(this, "Analyzing jalr $v0 at " + instr.getAddress());
						}
					} else {
						v1Count++;
					}

					// Look backward for the call that precedes this indirect call
					Function callingFunction = findFunctionThatReturnsPointer(program, instr, targetReg);
					if (callingFunction != null) {
						functionPointerReturners.put(callingFunction,
							functionPointerReturners.getOrDefault(callingFunction, 0) + 1);
						patternsFound++;
					} else {
						// If we see any prior call (even unresolved target), count pattern coverage
						if (hasPriorCallBeforeIndirect(program, instr)) {
							patternsFound++;
						}
					}
				}
			}
		}

		Msg.info(this, "Scanned " + totalInstructions + " instructions, found " + jalrCount + " jalr/jr instructions");
		Msg.info(this, "Found " + v0Count + " jalr/jr using $v0, " + v1Count + " using $v1");
		Msg.info(this, "Found " + patternsFound + " patterns where return values are used in indirect calls");
		Msg.info(this, "Identified " + functionPointerReturners.size() + " functions that return function pointers");

		// Phase 2: Fix function signatures
		for (Map.Entry<Function, Integer> entry : functionPointerReturners.entrySet()) {
			monitor.checkCancelled();
			Function func = entry.getKey();
			int count = entry.getValue();

			// Only fix if we see the pattern at least once
			if (count > 0) {
				if (fixFunctionSignature(program, func, count)) {
					signaturesFixed++;
				}
			}
		}

		Msg.info(this, "Fixed " + signaturesFixed + " function signatures to return function pointers");

		return signaturesFixed > 0;
	}

	/**
	 * Find the function that was called (jal) whose return value is used in jalr/jr.
	 */
	private Function findFunctionThatReturnsPointer(Program program, Instruction jalrInstr, Register targetReg) {
		// Search backward for jal instruction
		// IMPORTANT: In MIPS, there's a delay slot after jal, so the pattern is:
		//   jal function
		//   <delay slot instruction>  # executed BEFORE the jump
		//   jalr $v0                  # uses return value

		// Get the function containing this jalr to limit our search
		Function containingFunc = program.getFunctionManager().getFunctionContaining(jalrInstr.getAddress());
		Function functionScope = containingFunc;

		Instruction current = jalrInstr.getPrevious();
		int count = 0;

		while (current != null) {
			count++;

			// Stop if we've left the containing function
			Function curFunc = program.getFunctionManager().getFunctionContaining(current.getAddress());
			if (functionScope != null && curFunc != functionScope) {
				break;
			}

			String mnemonic = current.getMnemonicString();

			// Log first 20 instructions for the first jalr site to debug (address placeholder)
			if (count <= 20 && jalrInstr.getAddress().toString().equals("0001066c")) {
				Msg.info(this, "  [" + jalrInstr.getAddress() + "] Checking instruction " + count +
					" at " + current.getAddress() + ": " + mnemonic);
			}

			// Look for any prior call (direct jal/bal or PIC-style jalr/bal* with link)
			if (current.getFlowType() != null && current.getFlowType().isCall()) {
				// Loosen adjacency: allow a small window back to the prior call,
				// but still guard the delay slot overwrite case.
				final int MAX_BACKWARD_INSNS = 6; // includes delay slot (=1) and jal (=2)
				if (count > MAX_BACKWARD_INSNS) {
					break;
				}
				if (count == 2) {
					Instruction delay = jalrInstr.getPrevious();
					if (delay != null) {
						Register dst = delay.getRegister(0);
						if (dst != null && targetReg != null && dst.getName().equals(targetReg.getName())) {
							// Delay slot overwrites v0/v1; not a valid return-value pattern
							break;
						}
					}
				}
				Address targetAddr = null;

				// Prefer flow references
				Reference[] refs = current.getReferencesFrom();
				for (Reference ref : refs) {
					if (ref.getReferenceType().isCall() && !ref.getToAddress().isExternalAddress()) {
						targetAddr = ref.getToAddress();
						break;
					}
				}

				// Fallback: operand objects may contain an Address (direct calls)
				if (targetAddr == null && current.getNumOperands() > 0) {
					Object[] opObjs = current.getOpObjects(0);
					if (opObjs != null && opObjs.length > 0 && opObjs[0] instanceof Address) {
						targetAddr = (Address) opObjs[0];
					}
				}

				if (targetAddr != null) {
					Function targetFunc = program.getFunctionManager().getFunctionAt(targetAddr);
					if (targetFunc != null) {
						Msg.info(this, "Found pattern: " + targetFunc.getName() +
							" @ " + targetFunc.getEntryPoint() +
							" returns function pointer (used at " + jalrInstr.getAddress() + ")");
						return targetFunc;
					}
				}
				// No direct target address; try PIC-style callee resolution before giving up
				Function picResolved = resolvePicCallCallee(program, current, functionScope);
				if (picResolved != null) {
					Msg.info(this, "Resolved PIC callee for call at " + current.getAddress() +
						" -> " + picResolved.getName() + " @ " + picResolved.getEntryPoint());
					return picResolved;
				}
				// Could not resolve; stop the search and let outer logic count pattern if applicable


				break;


			}

			// DON'T stop if we see an instruction that writes to the target register
			// because in MIPS, the delay slot instruction after jal might write to $v0
			// We need to keep searching for the jal instruction

			current = current.getPrevious();
		}

		return null;
	}

	/**
	 * Fix the function signature to return a function pointer.
	 */
	private boolean fixFunctionSignature(Program program, Function func, int usageCount) {
		try {
			// Check if already returns a pointer or function pointer
			DataType currentReturnType = func.getReturnType();
			if (currentReturnType instanceof FunctionDefinition ||
			    currentReturnType instanceof Pointer) {
				Msg.debug(this, "Function " + func.getName() + " already returns pointer type, skipping");
				return false;
			}

			// Create a generic function pointer type
			// typedef void (*callback_t)(void);
			DataTypeManager dtm = program.getDataTypeManager();

			// Create function signature: void function(void)
			FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType("callback");
			funcDef.setReturnType(VoidDataType.dataType);
			funcDef.setArguments(new ParameterDefinition[0]);

			// Create pointer to function
			Pointer funcPtr = new PointerDataType(funcDef, dtm);

			// Update the function's return type
			func.setReturnType(funcPtr, SourceType.ANALYSIS);

			Msg.info(this, "Updated " + func.getName() + " to return function pointer " +
				"(used " + usageCount + " times in indirect calls)");

			return true;

		} catch (InvalidInputException e) {
			Msg.warn(this, "Failed to update signature for " + func.getName() + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Extract the jump target register from a jalr/jr instruction.
	 * Prefer a non-$ra register if multiple registers are present.
	 */
	private Register getJumpTargetRegister(Instruction instr) {
		try {
				// Try direct register access first (handle jalr $ra, $v0 and jr $v0 forms)
				Register r0 = instr.getRegister(0);
				Register r1 = instr.getRegister(1);
				if (r1 != null && !"ra".equals(r1.getName())) return r1;
				if (r0 != null && !"ra".equals(r0.getName())) return r0;
				if (r1 != null) return r1;
				if (r0 != null) return r0;



			int numOperands = instr.getNumOperands();
			Register candidate = null;
			for (int op = 0; op < numOperands; op++) {
				Object[] objs = instr.getOpObjects(op);
				for (Object obj : objs) {
					if (obj instanceof Register) {
						Register r = (Register) obj;
						if (!"ra".equals(r.getName())) {
							return r; // first non-ra register is our jump target
						}
						if (candidate == null) {
							candidate = r; // fallback if only $ra is present


						}
					}
				}
			}
			return candidate;
		} catch (Exception e) {
			return null;
		}
	}


	/**
	 * Lightweight check: is there any prior call before the given jalr/jr within the same function?

		 */

		/**
		 * Resolve PIC-style callee for a register-indirect call (e.g., jalr $t9) by
		 * scanning for hi/lo pairs and gp-relative loads feeding the call register.
		 */
		private Function resolvePicCallCallee(Program program, Instruction callInstr, Function scope) {
			try {
				Register callReg = getJumpTargetRegister(callInstr);
				if (callReg == null) return null;
				String callRegName = callReg.getName();
				Instruction cur = callInstr.getPrevious();
				boolean lowSeen = false;
				long lowImm = 0;
				int scanned = 0;
				final int MAX_SCAN = 64;
				while (cur != null && scanned < MAX_SCAN) {
					Function curFunc = program.getFunctionManager().getFunctionContaining(cur.getAddress());
					if (scope != null && curFunc != scope) break;
					scanned++;
					String m = cur.getMnemonicString();
					if (m.startsWith("_")) m = m.substring(1);
					// gp-relative: lw callReg, off(gp) -> follow reference to GOT entry, read pointer
					if ("lw".equals(m)) {
						Register rd = cur.getRegister(0);
						if (rd != null && callRegName.equals(rd.getName())) {
							Reference[] refs = cur.getReferencesFrom();
							for (Reference ref : refs) {
								Address to = ref.getToAddress();
								if (to != null && to.isMemoryAddress()) {
									try {
										ghidra.program.model.mem.Memory mem = program.getMemory();
										int ptr = mem.getInt(to);
										long p = Integer.toUnsignedLong(ptr);
										ghidra.program.model.address.AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
										Address cand = space.getAddress(p);
										Function f = program.getFunctionManager().getFunctionAt(cand);
										if (f != null) return f;
									} catch (ghidra.program.model.mem.MemoryAccessException e) {
										// ignore and continue
									}
								}
							}
						}
					}
					// hi/lo pair: addiu/ori callReg, callReg, lo; earlier lui callReg, hi
					if (!lowSeen && ("addiu".equals(m) || "ori".equals(m))) {
						Register rd = cur.getRegister(0);


						Register rs = cur.getRegister(1);
						if (rd != null && rs != null && callRegName.equals(rd.getName()) && callRegName.equals(rs.getName())) {
							Object[] objs = cur.getOpObjects(Math.min(2, cur.getNumOperands()-1));
							for (Object o : objs) {
								if (o instanceof ghidra.program.model.scalar.Scalar) {
									lowImm = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
									lowSeen = true;
									break;
								}
							}
						}
					}
					else if (lowSeen && "lui".equals(m)) {
						Register rd = cur.getRegister(0);
						if (rd != null && callRegName.equals(rd.getName())) {
							Object[] objs = cur.getOpObjects(Math.min(1, cur.getNumOperands()-1));
							for (Object o : objs) {
								if (o instanceof ghidra.program.model.scalar.Scalar) {
									long hi = ((ghidra.program.model.scalar.Scalar)o).getUnsignedValue() & 0xffffL;
									long lo = lowImm & 0xffffL;
									long addrVal = (hi << 16) | lo;
									ghidra.program.model.address.AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
									Address addr = space.getAddress(addrVal);
									Function f = program.getFunctionManager().getFunctionAt(addr);
									if (f != null) return f;
								}
							}
						}
					}
					cur = cur.getPrevious();
				}
			} catch (Exception e) {
				// ignore and return null
			}
			return null;
		}

	private boolean hasPriorCallBeforeIndirect(Program program, Instruction jalrInstr) {
		Function scope = program.getFunctionManager().getFunctionContaining(jalrInstr.getAddress());
		Instruction cur = jalrInstr.getPrevious();
		while (cur != null) {
			Function curFunc = program.getFunctionManager().getFunctionContaining(cur.getAddress());
			if (scope != null && curFunc != scope) {
				return false; // left the function
			}
			if (cur.getFlowType() != null && cur.getFlowType().isCall()) {
				return true;
			}
			cur = cur.getPrevious();
		}
		return false;
	}

}

