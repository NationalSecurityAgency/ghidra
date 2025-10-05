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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
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
						Msg.debug(this, "Skipping jalr/jr at " + instr.getAddress() + ": could not extract target register");
						if (jalrCount <= 10) {
							Msg.info(this, "Site " + jalrCount + ": mnemonic=" + mnemonic + ", addr=" + instr.getAddress());
						}
					}
					continue;
				}

				// Resolve simple aliases to return registers (e.g., move/addu/or with $zero): s1 <- v0
				Register effTargetReg = resolveAliasRegister(program, instr, targetReg, 6);

				// Debug: candidate site classification (use effective target)
				if ("v0".equals(effTargetReg.getName()) || "v1".equals(effTargetReg.getName())) {
					Msg.info(this, "Candidate return-value jalr/jr at " + instr.getAddress() + " using $" + effTargetReg.getName());
				}

				// New: For any target register, if it was loaded from a param/saved/sp base, force CALL_RETURN tailcall
				if (!"v0".equals(effTargetReg.getName()) && !"v1".equals(effTargetReg.getName())) {
					if (recentMemLoadIntoTargetFromParamBase(instr, effTargetReg, 10)) {
						try { instr.setFlowOverride(FlowOverride.CALL_RETURN); } catch (Exception ignore) {}
						// Ensure wrapper has minimally-needed params inferred from usage and callers
						Function wrap = program.getFunctionManager().getFunctionContaining(instr.getAddress());
						int need = Math.max(inferMinParamsForTrampoline(program, instr, 40),
						                     inferParamsFromCallers(program, wrap, 16, 40));
						ensureMinParams(program, wrap, need);
						if (jalrCount <= 10) {
							Msg.info(this, "Set FlowOverride=CALL_RETURN at " + instr.getAddress() + " (trampoline tailcall)");
						}
					}
				}

				// Check if effective target register is $v0 or $v1 (return value registers)
				if ("v0".equals(effTargetReg.getName()) || "v1".equals(effTargetReg.getName())) {
					// Guard: if we just loaded v0/v1 from [a0..a3/s0..s7]+off, treat as trampoline and skip FP-return classification
					if (recentMemLoadIntoTargetFromParamBase(instr, effTargetReg, 10)) {
						// Force decompiler to treat jr/jalr as a call (tailcall) at this site
						try { instr.setFlowOverride(FlowOverride.CALL_RETURN); } catch (Exception ignore) {}
						// Ensure wrapper has minimally-needed params inferred from usage and callers
						Function wrap = program.getFunctionManager().getFunctionContaining(instr.getAddress());
						int need = Math.max(inferMinParamsForTrampoline(program, instr, 40),
						                     inferParamsFromCallers(program, wrap, 16, 40));
						ensureMinParams(program, wrap, need);
						if (jalrCount <= 10) {
							Msg.info(this, "Skip FP-return classification at " + instr.getAddress() +
								" (likely trampoline): set FlowOverride=CALL_RETURN");
						}
						continue; // do not mark any callee as function-pointer-returner
					}
					if ("v0".equals(effTargetReg.getName())) {
						v0Count++;
						if (v0Count <= 3) {
							Msg.info(this, "Analyzing jalr $v0 (aliased) at " + instr.getAddress());
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
		 * Backward-slice the jalr/jr target register a few instructions to resolve
		 * simple aliases to $v0/$v1 (e.g., move/addu/or-with-zero, addiu from v0/v1).
		 */
		private Register resolveAliasRegister(Program program, Instruction jalrInstr, Register targetReg, int maxBack) {
			if (targetReg == null) return null;
			String name = targetReg.getName();
			if ("v0".equals(name) || "v1".equals(name)) return targetReg;
			Instruction cur = jalrInstr.getPrevious();
			int scanned = 0;
			while (cur != null && scanned < maxBack) {
				scanned++;
				String m = cur.getMnemonicString();
				if (m.startsWith("_")) m = m.substring(1);
				try {
					Register dst = cur.getRegister(0);
					Register s1 = cur.getRegister(1);
					Register s2 = cur.getRegister(2);
					if (dst != null && name.equals(dst.getName())) {
						if ("move".equals(m)) {
							if (s1 != null && ("v0".equals(s1.getName()) || "v1".equals(s1.getName()))) return s1;
						} else if ("addu".equals(m) || "or".equals(m)) {
							Register other = null;
							if (s1 != null && "zero".equals(s2 != null ? s2.getName() : "")) other = s1;
							else if (s2 != null && "zero".equals(s1 != null ? s1.getName() : "")) other = s2;
							if (other != null && ("v0".equals(other.getName()) || "v1".equals(other.getName()))) return other;
						} else if ("addiu".equals(m)) {
							if (s1 != null && ("v0".equals(s1.getName()) || "v1".equals(s1.getName()))) return s1;
						}
					}
				} catch (Exception ignore) {}
				cur = cur.getPrevious();
			}
			return targetReg;
		}
		/**
		 * Detect if the effective call target register was recently loaded from memory
		 * using a base register that looks like a parameter/base pointer (a0..a3/s0..s7).
		 * This is a hallmark of tail-call trampolines: load fp from struct field then jalr.
		 */
		private boolean recentMemLoadIntoTargetFromParamBase(Instruction jalrInstr, Register effTargetReg, int maxBack) {
			if (effTargetReg == null) return false;
			String target = effTargetReg.getName();
			java.util.Set<String> baseWhitelist = new java.util.HashSet<>(java.util.Arrays.asList(
				"a0","a1","a2","a3",
				"s0","s1","s2","s3","s4","s5","s6","s7"
			));
			Instruction cur = jalrInstr.getPrevious();
			int scanned = 0;
			while (cur != null && scanned < maxBack) {
				scanned++;
				String m = cur.getMnemonicString();
				if (m.startsWith("_")) m = m.substring(1);
				if ("lw".equals(m) || "lbu".equals(m) || "lhu".equals(m) || "lwu".equals(m) || "lb".equals(m) || "lh".equals(m)) {
					try {
						Register dst = cur.getRegister(0);
						String baseName = null;
						// Operand text is like: off(a0)
						if (cur.getNumOperands() >= 2) {
							String op1 = cur.getDefaultOperandRepresentation(1);
							int o = op1.indexOf('(');
							int c = op1.indexOf(')');
							if (o >= 0 && c > o) {
								baseName = op1.substring(o + 1, c).trim();
							}
						}
						if (dst != null && target.equals(dst.getName()) && baseName != null) {
							if (baseWhitelist.contains(baseName)) {
								return true; // likely trampoline pattern
							}
						}
					} catch (Exception ignore) {}
				}
				cur = cur.getPrevious();
			}
			return false;
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


	/** Ensure the containing function has at least `min` parameters (A0..).
	 *  Only expands count when current < min; retains existing param names/types.
	 */
	private void ensureMinParams(Program program, Function func, int min) {
		try {
			if (func == null) return;
			Parameter[] cur = func.getParameters();
			if (cur.length >= min) return;
			// Ensure dynamic storage is in effect and convention is sane
			try { if (func.hasCustomVariableStorage()) func.setCustomVariableStorage(false); } catch (Exception ignore) {}
			try { func.setCallingConvention(null); } catch (Exception ignore) {}
			java.util.List<Parameter> neu = new java.util.ArrayList<>();
			for (int i = 0; i < min; i++) {
				if (i < cur.length) {
					neu.add(new ParameterImpl(cur[i].getName(), cur[i].getDataType(), program));
				} else {
					neu.add(new ParameterImpl("param_" + (i + 1), Undefined4DataType.dataType, program));
				}
			}
			func.replaceParameters(neu, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
		} catch (Exception ignore) {}
	}


	/** Infer minimal number of a-register parameters (1..4) from callers of wrap.
	 *  We scan a limited number of call sites and look backwards for a0..a3 definitions.
	 */
	private int inferParamsFromCallers(Program program, Function wrap, int maxSites, int maxBack) {
		try {
			if (wrap == null) return 1;
			int need = 1;
			Address entry = wrap.getEntryPoint();
			int seen = 0;
			for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
				if (seen++ >= maxSites) break;
				Address from = ref.getFromAddress();
				Instruction call = program.getListing().getInstructionAt(from);
				if (call == null) continue;
				Instruction cur = call.getPrevious();
				int scanned = 0;
				java.util.Set<String> defined = new java.util.HashSet<>();
				int locNeed = 1;
				while (cur != null && scanned++ < maxBack) {
					String m = cur.getMnemonicString();
					if (m.startsWith("_")) m = m.substring(1);
					Register dst = null, s1 = null, s2 = null;
					try { dst = cur.getRegister(0); } catch (Exception ignore) {}
					try { s1 = cur.getRegister(1); } catch (Exception ignore) {}
					try { s2 = cur.getRegister(2); } catch (Exception ignore) {}
					if (dst != null) {
						String dn = dst.getName();
						if ("a0".equals(dn) || "a1".equals(dn) || "a2".equals(dn) || "a3".equals(dn)) defined.add(dn);
					}
					if (s1 != null) {
						String n = s1.getName();
						int idx = ("a0".equals(n)?0:("a1".equals(n)?1:("a2".equals(n)?2:("a3".equals(n)?3:-1))));
						if (idx >= 0 && defined.contains(n)) locNeed = Math.max(locNeed, idx+1);
					}
					if (s2 != null) {
						String n = s2.getName();
						int idx = ("a0".equals(n)?0:("a1".equals(n)?1:("a2".equals(n)?2:("a3".equals(n)?3:-1))));
						if (idx >= 0 && defined.contains(n)) locNeed = Math.max(locNeed, idx+1);
					}
					// off(aN) base used near call suggests aN was prepared
					if (cur.getNumOperands() >= 2) {
						String op1 = cur.getDefaultOperandRepresentation(1);
						int o = op1.indexOf('('), c = op1.indexOf(')');
						if (o >= 0 && c > o) {
							String baseName = op1.substring(o + 1, c).trim();
							int idx = ("a0".equals(baseName)?0:("a1".equals(baseName)?1:("a2".equals(baseName)?2:("a3".equals(baseName)?3:-1))));
							if (idx >= 0) locNeed = Math.max(locNeed, idx+1);
						}
					}
					cur = cur.getPrevious();
				}
				need = Math.max(need, locNeed);
			}
			return need;
		} catch (Exception e) {
			return 1;
		}
	}


	/** Infer minimal number of a-register parameters (1..4) a trampoline wrapper needs,
	 *  by scanning backwards from the jr/jalr and recording reads of a0..a3 that are
	 *  not preceded by a write in the scanned window (live-in).
	 */
	private int inferMinParamsForTrampoline(Program program, Instruction jrInstr, int maxBack) {
		try {
			java.util.Set<String> written = new java.util.HashSet<>();
			boolean[] need = new boolean[] { false, false, false, false };
			Instruction cur = jrInstr.getPrevious();
			int scanned = 0;
			Function scope = program.getFunctionManager().getFunctionContaining(jrInstr.getAddress());
			while (cur != null && scanned++ < maxBack) {
				Function f = program.getFunctionManager().getFunctionContaining(cur.getAddress());
				if (scope != null && f != scope) break; // left function
				String m = cur.getMnemonicString();
				if (m.startsWith("_")) m = m.substring(1);
				Register dst = null, src1 = null, src2 = null;
				try { dst = cur.getRegister(0); } catch (Exception ignore) {}
				try { src1 = cur.getRegister(1); } catch (Exception ignore) {}
				try { src2 = cur.getRegister(2); } catch (Exception ignore) {}
				// Track writes to aN
				if (dst != null) {
					String dn = dst.getName();
					if ("a0".equals(dn) || "a1".equals(dn) || "a2".equals(dn) || "a3".equals(dn)) {
						written.add(dn);
					}
				}
				// Reads from aN via register operands
				if (src1 != null) {
					String n = src1.getName();
					int idx = ("a0".equals(n)?0:("a1".equals(n)?1:("a2".equals(n)?2:("a3".equals(n)?3:-1))));
					if (idx >= 0 && !written.contains(n)) need[idx] = true;
				}
				if (src2 != null) {
					String n = src2.getName();
					int idx = ("a0".equals(n)?0:("a1".equals(n)?1:("a2".equals(n)?2:("a3".equals(n)?3:-1))));
					if (idx >= 0 && !written.contains(n)) need[idx] = true;
				}
				// Reads from aN via memory base: off(aN)
				if (cur.getNumOperands() >= 2) {
					String op1 = cur.getDefaultOperandRepresentation(1);
					int o = op1.indexOf('('), c = op1.indexOf(')');
					if (o >= 0 && c > o) {
						String baseName = op1.substring(o + 1, c).trim();
						int idx = ("a0".equals(baseName)?0:("a1".equals(baseName)?1:("a2".equals(baseName)?2:("a3".equals(baseName)?3:-1))));
						if (idx >= 0 && !written.contains(baseName)) need[idx] = true;
					}
				}
				cur = cur.getPrevious();
			}
			int max = 0;
			for (int i = 0; i < 4; i++) if (need[i]) max = i + 1;
			return Math.max(1, Math.min(4, max == 0 ? 1 : max));
		} catch (Exception e) {
			return 1;
		}
	}

}

