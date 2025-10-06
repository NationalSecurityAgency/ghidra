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

import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Post-decompiler pass: ensure the exact decompiler-chosen CALLIND target (pcVarX) is typed
 * as a function pointer so the decompiler prints arguments at jr/jalr trampolines.
 */
public class MipsDecompIndirectCallAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "MIPS Indirect Call Decomp Retype";
    private static final String DESCRIPTION =
        "After decompiling MIPS trampolines with jr/jalr, set the call target local (pcVarX) " +
        "to a function pointer type so arguments render.";

    // Options
    private static final String OPTION_TIMEOUT_MS = "Decompile timeout (ms)";
    private static final int DEFAULT_TIMEOUT_MS = 3000; // keep it snappy

    private int timeoutMs = DEFAULT_TIMEOUT_MS;

    public MipsDecompIndirectCallAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        // Run late so normal analysis and typing have occurred
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        Processor p = program.getLanguage().getProcessor();
        return p != null && "MIPS".equalsIgnoreCase(p.toString());
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, null,
            "Decompile timeout per function (milliseconds)");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        timeoutMs = options.getInt(OPTION_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor p = program.getLanguage().getProcessor();
        return p != null && "MIPS".equalsIgnoreCase(p.toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Listing listing = program.getListing();
        DecompInterface ifc = new DecompInterface();
        try {
            if (!ifc.openProgram(program)) {
                Msg.warn(this, "Decompile openProgram failed; skipping MIPS decomp retype pass");
                return false;
            }
            FunctionIterator fit = listing.getFunctions(set, true);
            while (fit.hasNext()) {
                monitor.checkCanceled();
                Function f = fit.next();
                if (!isMips(program) || f == null) continue;
                // Only consider functions with a jr/jalr to non-ra
                Address callSite = findTailComputedCall(program, f);
                if (callSite == null) continue;

                // Decompile the function and find CALLIND at/near the site
                DecompileResults res = ifc.decompileFunction(f, timeoutMs, monitor);
                HighFunction hf = res != null ? res.getHighFunction() : null;
                if (hf == null) continue;

                PcodeOpAST callind = findCallIndAt(hf, callSite);
                if (callind == null) continue;

                Varnode target = callind.getInput(0);
                if (target == null) continue;

                // Determine parameter count to build function pointer type
                int paramCount = Math.max(0, f.getParameterCount());
                PointerDataType funcPtr = new PointerDataType(createFuncDef("fp_sig" + paramCount, paramCount), program.getDataTypeManager());

                // Prefer retyping through the decompiler's HighSymbol and commit to DB
                HighVariable hv = target.getHigh();
                boolean applied = false;
                if (hv != null) {
                    try {
                        ghidra.program.model.pcode.HighSymbol hs = hv.getSymbol();
                        if (hs != null) {
                            int tx = program.startTransaction("MIPS Indirect Call Retype");
                            try {
                                DataType resolved = program.getDataTypeManager().resolve(funcPtr, null);
                                String hvName = hv.getName();
                                String newName = (hvName != null && hvName.startsWith("UNRECOVERED_JUMPTABLE")) ? "callTarget" : null;
                                HighFunctionDBUtil.updateDBVariable(hs, newName, resolved, SourceType.USER_DEFINED);
                                applied = true;
                            } catch (Exception e) {
                                // fall back below
                            } finally {
                                program.endTransaction(tx, applied);
                            }
                            // Hint the decompiler to keep the type and name once set
                            try { hs.setTypeLock(true); } catch (Exception ignore) {}
                            try { hs.setNameLock(true); } catch (Exception ignore) {}
                        }
                    } catch (Exception ignore) {}
                    if (!applied) {
                        String hvName = hv.getName();
                        if (hvName != null) {
                            applied = retypeLocalByName(program, f, hvName, funcPtr);
                        }
                    }
                }
                // Fallback: map by register storage, if register-backed
                if (!applied && target.isRegister()) {
                    Register reg = program.getRegister(target.getAddress());
                    if (reg != null) {
                        applied = retypeLocalByRegister(program, f, reg, funcPtr);
                    }
                }
                // Last resort: pcVar* sweep
                if (!applied) {
                    applied = retypeAnyPcVar(program, f, funcPtr);
                }

                if (applied) {
                    Msg.info(this, String.format("[MipsDecompIndirectCallAnalyzer] Retyped call target at %s in %s", callSite, f.getName()));
                }
            }
        } finally {
            ifc.dispose();
        }
        return true;
    }

    private boolean isMips(Program program) {
        Processor p = program.getLanguage().getProcessor();
        return p != null && "MIPS".equalsIgnoreCase(p.toString());
    }

    private Address findTailComputedCall(Program program, Function f) {
        Listing listing = program.getListing();
        InstructionIterator it = listing.getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction in = it.next();
            String m = in.getMnemonicString();
            if ("jr".equals(m) || "jalr".equals(m) || "_jr".equals(m) || "_jalr".equals(m)) {
                Register r0 = null, r1 = null;
                try { r0 = in.getRegister(0); } catch (Exception ignore) {}
                try { r1 = in.getRegister(1); } catch (Exception ignore) {}
                Register tgt = (r1 != null) ? r1 : r0;
                if (tgt != null && !"ra".equals(tgt.getName())) {
                    return in.getAddress();
                }
            }
        }
        return null;
    }

    private PcodeOpAST findCallIndAt(HighFunction hf, Address site) {
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        PcodeOpAST best = null;
        long bestDelta = Long.MAX_VALUE;
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            if (op.getOpcode() == PcodeOp.CALLIND) {
                Address a = op.getSeqnum().getTarget();
                if (a != null) {
                    long d = Math.abs(a.subtract(site));
                    if (d < bestDelta) { bestDelta = d; best = op; }
                }
            }
        }
        return best;
    }

    private FunctionDefinitionDataType createFuncDef(String name, int paramCount) {
        FunctionDefinitionDataType def = new FunctionDefinitionDataType(name);
        def.setReturnType(VoidDataType.dataType);
        if (paramCount > 0) {
            ParameterDefinition[] params = new ParameterDefinition[paramCount];
            for (int i = 0; i < paramCount; i++) {
                params[i] = new ParameterDefinitionImpl("param_" + (i + 1), Undefined4DataType.dataType, "");
            }
            def.setArguments(params);
        }
        return def;
    }

    private boolean retypeLocalByName(Program program, Function f, String name, DataType dt) {
        try {
            for (Variable v : f.getLocalVariables()) {
                if (name.equals(v.getName())) {
                    v.setDataType(dt, SourceType.USER_DEFINED);
                    return true;
                }
            }
        } catch (Exception ignore) {}
        return false;
    }

    private boolean retypeLocalByRegister(Program program, Function f, Register reg, DataType dt) {
        try {
            for (Variable v : f.getLocalVariables()) {
                Register r = v.getRegister();
                if (r != null && r.equals(reg)) {
                    v.setDataType(dt, SourceType.USER_DEFINED);
                    return true;
                }
            }
            // If not found, add a new local anchored near entry using this register
            int anchor = 0;
            try { anchor = (int) (f.getEntryPoint().subtract(f.getEntryPoint())); } catch (Exception ignore) {}
            LocalVariable lv = new LocalVariableImpl("pcVar_fp", anchor, dt, reg, program);
            f.addLocalVariable(lv, SourceType.USER_DEFINED);
            return true;
        } catch (Exception ignore) {}
        return false;
    }

    private boolean retypeAnyPcVar(Program program, Function f, DataType dt) {
        boolean any = false;
        try {
            for (Variable v : f.getLocalVariables()) {
                String nm = v.getName();
                if (nm != null && nm.startsWith("pcVar")) {
                    try {
                        if (v.getSource() != SourceType.USER_DEFINED) {
                            v.setDataType(dt, SourceType.USER_DEFINED);
                        }
                        any = true;
                    } catch (Exception ignoreInner) {}
                }
            }
        } catch (Exception ignore) {}
        return any;
    }
}

