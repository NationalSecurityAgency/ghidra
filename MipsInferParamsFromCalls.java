/* ###
 * IP: GHIDRA
 */
// Script: Infer MIPS parameter counts from call sites and tailcall trampolines
// @category Analysis.MIPS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;

import java.util.*;

public class MipsInferParamsFromCalls extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("No program loaded");
            return;
        }
        if (!currentProgram.getLanguage().getProcessor().toString().toLowerCase().contains("mips")) {
            println("This script is intended for MIPS");
            return;
        }

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        Register a0 = currentProgram.getRegister("a0");
        Register a1 = currentProgram.getRegister("a1");
        Register a2 = currentProgram.getRegister("a2");
        Register a3 = currentProgram.getRegister("a3");

        Map<Function,Integer> inferred = new HashMap<>();
        Set<Function> visitedFuncs = new HashSet<>();

        println("Scanning calls to infer parameter counts...");
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction instr = it.next();
            Function containing = fm.getFunctionContaining(instr.getAddress());
            if (containing != null) visitedFuncs.add(containing);
            if (instr.getFlowType() == null || !instr.getFlowType().isCall()) continue;

            Address calleeAddr = null;
            for (Reference ref : instr.getReferencesFrom()) {
                if (ref.getReferenceType().isCall() && !ref.getToAddress().isExternalAddress()) {
                    calleeAddr = ref.getToAddress();
                    break;
                }
            }
            if (calleeAddr == null && instr.getNumOperands() > 0) {
                Object[] objs = instr.getOpObjects(0);
                if (objs != null && objs.length > 0 && objs[0] instanceof Address) {
                    calleeAddr = (Address) objs[0];
                }
            }
            if (calleeAddr == null) continue;
            Function callee = fm.getFunctionAt(calleeAddr);
            if (callee == null) continue;

            int window = 12;
            int scanned = 0;
            boolean[] wrote = new boolean[4];
            Instruction cur = instr.getPrevious();
            while (cur != null && scanned++ < window) {
                Register dst = cur.getRegister(0);
                if (dst != null) {
                    String n = dst.getName();
                    if ("a0".equals(n)) wrote[0] = true;
                    else if ("a1".equals(n)) wrote[1] = true;
                    else if ("a2".equals(n)) wrote[2] = true;
                    else if ("a3".equals(n)) wrote[3] = true;
                }
                cur = cur.getPrevious();
            }
            int localParams = 0;
            for (int i = 3; i >= 0; i--) {
                if (wrote[i]) { localParams = i+1; break; }
            }
            inferred.merge(callee, localParams, Math::max);
        }

        // Tailcall trampoline heuristic: jr/jalr $t9, writes a0 somewhere, no writes to a1..a3
        println("Scanning for tailcall trampolines...");
        for (Function f : visitedFuncs) {
            if (monitor.isCancelled()) break;
            try {
                InstructionIterator fi = listing.getInstructions(f.getBody(), true);
                boolean wroteA0=false, wroteA1=false, wroteA2=false, wroteA3=false;
                Instruction last = null;
                while (fi.hasNext()) {
                    Instruction ins = fi.next();
                    last = ins;
                    Register dst = ins.getRegister(0);
                    if (dst != null) {
                        String n = dst.getName();
                        if ("a0".equals(n)) wroteA0 = true;
                        else if ("a1".equals(n)) wroteA1 = true;
                        else if ("a2".equals(n)) wroteA2 = true;
                        else if ("a3".equals(n)) wroteA3 = true;
                    }
                }
                if (last != null) {
                    String m = last.getMnemonicString();
                    if (m.startsWith("_")) m = m.substring(1);
                    if (("jr".equals(m) || "jalr".equals(m))) {
                        Register r0 = last.getRegister(0);
                        Register r1 = last.getRegister(1);
                        Register tgt = (r1 != null && !"ra".equals(r1.getName())) ? r1 : r0;
                        if (tgt != null && "t9".equals(tgt.getName())) {
                            if (!wroteA1 && !wroteA2 && !wroteA3) {
                                inferred.merge(f, 3, Math::max);
                            }
                        }
                    }
                }
            } catch (Exception ignore) { }
        }

        int adjusted = 0;
        for (Map.Entry<Function,Integer> e : inferred.entrySet()) {
            Function f = e.getKey();
            int want = e.getValue();
            if (want <= f.getParameterCount()) continue;
            try {
                List<Parameter> params = new ArrayList<>();
                for (int i=0; i<want; i++) {
                    params.add(new ParameterImpl("param_"+(i+1), Undefined4DataType.dataType, currentProgram));
                }
                f.updateFunction(null, null, params, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
                adjusted++;
                println("Adjusted parameter count for "+f.getName()+" to "+want);
            } catch (Exception ex) {
                println("Failed to adjust "+f.getName()+": "+ex.getMessage());
            }
        }
        println("Done. Adjusted "+adjusted+" function parameter lists.");
    }
}

