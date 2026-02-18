/* ###
 * IP: GHIDRA
 */
// Script: Detect MIPS tail-call trampolines and fix signatures (unlock storage, set 3 params, sane return)
// @category Analysis.MIPS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class MipsFixTailcallWrappers extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) { println("No program loaded"); return; }
        if (!currentProgram.getLanguage().getProcessor().toString().toLowerCase().contains("mips")) {
            println("This script is intended for MIPS programs"); return;
        }

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        Register a0 = currentProgram.getRegister("a0");
        Register a1 = currentProgram.getRegister("a1");
        Register a2 = currentProgram.getRegister("a2");
        Register a3 = currentProgram.getRegister("a3");
        Register t9 = currentProgram.getRegister("t9");
        Register ra = currentProgram.getRegister("ra");

        int candidates = 0, updates = 0;
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            try {
                boolean wroteA1=false, wroteA2=false, wroteA3=false;
                boolean sawJrT9=false, sawJalrT9=false;
                boolean sawJrRa=false; // some wrappers have an error-return via jr $ra

                InstructionIterator it = listing.getInstructions(f.getBody(), true);
                while (it.hasNext()) {
                    Instruction ins = it.next();
                    Register dst = null;
                    try { dst = ins.getRegister(0); } catch (Exception ignore) {}
                    if (dst != null) {
                        String n = dst.getName();
                        if ("a1".equals(n)) wroteA1 = true;
                        else if ("a2".equals(n)) wroteA2 = true;
                        else if ("a3".equals(n)) wroteA3 = true;
                    }
                    String m = ins.getMnemonicString();
                    if (m.startsWith("_")) m = m.substring(1);
                    if ("jr".equals(m) || "jalr".equals(m)) {
                        // target may be operand reg 0 or 1 depending on form
                        Register r0 = null, r1 = null;
                        try { r0 = ins.getRegister(0); } catch (Exception ignore) {}
                        try { r1 = ins.getRegister(1); } catch (Exception ignore) {}
                        Register tgt = (r1 != null && !"ra".equals(r1.getName())) ? r1 : r0;
                        if (tgt != null && t9 != null && tgt.equals(t9)) {
                            if ("jr".equals(m)) sawJrT9 = true; else sawJalrT9 = true;
                        }
                        if (tgt != null && ra != null && tgt.equals(ra)) {
                            sawJrRa = true;
                        }
                    }
                }

                // Heuristic: tail-call trampoline when it can jump via t9 and doesn't touch a1..a3
                if ((sawJrT9 || sawJalrT9) && !wroteA1 && !wroteA2 && !wroteA3) {
                    candidates++;
                    // Build new params (at least 3 arguments), and unlock storage so a0..a2 get assigned
                    int want = Math.max(3, f.getParameterCount());
                    java.util.List<Parameter> params = new ArrayList<>(want);
                    for (int i=0; i<want; i++) {
                        params.add(new ParameterImpl("param_"+(i+1), Undefined4DataType.dataType, currentProgram));
                    }

                    // If return type currently looks like a function pointer and there is also a jr $ra path,
                    // prefer an integer return (common wrappers return error codes on failure path)
                    DataType ret = f.getReturnType();
                    boolean looksFuncPtr = (ret instanceof Pointer) || (ret instanceof FunctionDefinition);
                    if (looksFuncPtr && sawJrRa) {
                        try { f.setReturnType(Undefined4DataType.dataType, SourceType.USER_DEFINED); } catch (Exception ignore) {}
                    }

                    try {
                        if (f.hasCustomVariableStorage()) {
                            f.setCustomVariableStorage(false);
                        }
                        // Reset to default calling convention so storage is auto-assigned
                        try { f.setCallingConvention(null); } catch (Exception ignore) {}
                        // Apply 3+ params and mark as USER_DEFINED so analyzers won't shrink it back
                        f.updateFunction(null, null, params, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED);
                        // Lock current storage so parameter count stays stable even if params are not referenced locally
                        try { f.setCustomVariableStorage(true); } catch (Exception ignore) {}
                        updates++;
                        println("Updated wrapper signature: "+f.getName()+" to "+want+" params (locked storage)");
                    } catch (Exception ex) {
                        println("Failed updating "+f.getName()+": "+ex.getMessage());
                    }
                }
            } catch (Exception ignore) { }
        }

        println("Tail-call wrapper candidates: "+candidates+", updated: "+updates);
    }
}

