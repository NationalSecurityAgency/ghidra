/* ###
 * IP: GHIDRA
 */
// Script: Infer struct types from repeated field-offset usage on pointer parameters (MIPS)
// @category Analysis.MIPS
// @author Augment

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;

import java.util.*;

public class GenericStructFromFieldUsage extends GhidraScript {

    private static class ParamKey {
        final int paramIndex; // 0=a0..3=a3
        final List<Integer> signature; // sorted unique offsets
        ParamKey(int idx, Set<Integer> offs) {
            this.paramIndex = idx;
            List<Integer> s = new ArrayList<>(offs);
            Collections.sort(s);
            this.signature = Collections.unmodifiableList(s);
        }
        @Override public boolean equals(Object o){
            if (!(o instanceof ParamKey)) return false;
            ParamKey k=(ParamKey)o; return paramIndex==k.paramIndex && signature.equals(k.signature);
        }
        @Override public int hashCode(){ return Objects.hash(paramIndex, signature); }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) { println("No program loaded"); return; }
        if (!currentProgram.getLanguage().getProcessor().toString().toLowerCase().contains("mips")) {
            println("This script is intended for MIPS programs"); return;
        }

        // Configuration
        final int MIN_OFFSETS_PER_FUNC = 2;   // require at least N distinct offsets seen in a function for a param
        final int MIN_FUNCS_PER_CLUSTER = 5;  // only create/apply a struct when >= N functions share the same signature
        final int MAX_STRUCT_SIZE_PAD = 4;    // pad to 4-byte boundary
        final Set<String> MEM_OPS = new HashSet<>(Arrays.asList(
            "lw","sw","lb","sb","lh","sh","lhu","lbu","lwu","swr","lwr"));

        Register a0 = currentProgram.getRegister("a0");
        Register a1 = currentProgram.getRegister("a1");
        Register a2 = currentProgram.getRegister("a2");
        Register a3 = currentProgram.getRegister("a3");
        Register[] argRegs = new Register[]{a0,a1,a2,a3};

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        // 1) Gather per-function, per-paramIndex distinct offsets used in memory ops base(param)
        Map<Function, Map<Integer, Set<Integer>>> funcParamOffsets = new HashMap<>();

        FunctionIterator fit = fm.getFunctions(true);
        int funcsScanned = 0;
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            funcsScanned++;
            Map<Integer, Set<Integer>> perParam = new HashMap<>();
            InstructionIterator iit = listing.getInstructions(f.getBody(), true);
            while (iit.hasNext()) {
                Instruction ins = iit.next();
                String m = ins.getMnemonicString();
                if (m.startsWith("_")) m = m.substring(1);
                if (!MEM_OPS.contains(m)) continue;
                // Expect form: <op> rt, imm(base)
                Register base = null;
                try { base = ins.getRegister(1); } catch (Exception ignore) {}
                if (base == null) continue;
                int pidx = -1;
                for (int i=0;i<argRegs.length;i++) {
                    if (argRegs[i] != null && base.equals(argRegs[i])) { pidx = i; break; }
                }
                if (pidx < 0) continue; // not an a0..a3-based access
                // Find immediate offset
                Integer off = null;
                for (int op=0; op<ins.getNumOperands(); op++) {
                    Object[] objs = ins.getOpObjects(op);
                    if (objs == null) continue;
                    for (Object o : objs) {
                        if (o instanceof ghidra.program.model.scalar.Scalar) {
                            long v = ((ghidra.program.model.scalar.Scalar)o).getSignedValue();
                            // Heuristic: treat 16-bit immediates as the offset
                            if (v >= -0x8000 && v <= 0x7fff) {
                                off = (int)v; break;
                            }
                        }
                    }
                    if (off != null) break;
                }
                if (off == null) continue;
                // Only positive/zero offsets for struct fields; skip negative stack-like
                if (off < 0) continue;
                perParam.computeIfAbsent(pidx,k->new HashSet<>()).add(off);
            }
            if (!perParam.isEmpty()) funcParamOffsets.put(f, perParam);
        }

        // 2) Build clusters by (paramIndex, sorted offsets signature)
        Map<ParamKey, List<Function>> clusters = new HashMap<>();
        for (Map.Entry<Function, Map<Integer, Set<Integer>>> e : funcParamOffsets.entrySet()) {
            Function f = e.getKey();
            for (Map.Entry<Integer, Set<Integer>> pe : e.getValue().entrySet()) {
                int pidx = pe.getKey();
                Set<Integer> offs = pe.getValue();
                if (offs.size() < MIN_OFFSETS_PER_FUNC) continue;
                ParamKey key = new ParamKey(pidx, offs);
                clusters.computeIfAbsent(key, k->new ArrayList<>()).add(f);
            }
        }

        // 3) Create structs for high-confidence clusters and apply to functions
        int structsCreated = 0, paramsTyped = 0;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        for (Map.Entry<ParamKey, List<Function>> c : clusters.entrySet()) {
            if (monitor.isCancelled()) break;
            ParamKey key = c.getKey();
            List<Function> funcs = c.getValue();
            if (funcs.size() < MIN_FUNCS_PER_CLUSTER) continue;

            // Create a unique name from signature
            String sigPart = key.signature.toString().replace(" ","").replace(",","_").replace("[","").replace("]","");
            String structName = String.format("inferred_param%d_s_%s", key.paramIndex+1, sigPart);
            StructureDataType sdt = new StructureDataType(structName, 0);

            // Add fields at observed offsets; default each field size 4
            int maxEnd = 0;
            for (int off : key.signature) {
                // Align padding to offset
                if (sdt.getLength() < off) {
                    int pad = off - sdt.getLength();
                    sdt.add(new ArrayDataType(ByteDataType.dataType, pad, 1), "_pad_"+sdt.getLength(), null);
                }
                // Add a 4-byte field
                sdt.add(Undefined4DataType.dataType, 4, String.format("f_%04x", off), null);
                maxEnd = Math.max(maxEnd, off+4);
            }
            // Final pad to align struct end
            int padTo = ((maxEnd + (MAX_STRUCT_SIZE_PAD-1)) / MAX_STRUCT_SIZE_PAD) * MAX_STRUCT_SIZE_PAD;
            if (sdt.getLength() < padTo) {
                sdt.add(new ArrayDataType(ByteDataType.dataType, padTo - sdt.getLength(), 1), "_pad_end", null);
            }

            // Apply to all functions in the cluster
            PointerDataType ptrType = new PointerDataType(sdt);
            for (Function f : funcs) {
                try {
                    Parameter[] old = f.getParameters();
                    if (key.paramIndex >= old.length) continue; // function has fewer formals
                    // Only update if the current type is undefined or a generic pointer
                    DataType cur = old[key.paramIndex].getDataType();
                    boolean safeToReplace = (cur instanceof Undefined || cur instanceof Undefined4DataType ||
                                             cur instanceof PointerDataType);
                    if (!safeToReplace) continue;
                    Parameter[] neu = new Parameter[old.length];
                    for (int i=0;i<old.length;i++) {
                        if (i==key.paramIndex) neu[i] = new ParameterImpl(old[i].getName(), ptrType, currentProgram);
                        else neu[i] = new ParameterImpl(old[i].getName(), old[i].getDataType(), currentProgram);
                    }
                    f.replaceParameters(Arrays.asList(neu), FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
                    paramsTyped++;
                } catch (Exception ex) {
                    println("Skip "+f.getName()+": "+ex.getMessage());
                }
            }
            // Commit struct
            dtm.addDataType(sdt, DataTypeConflictHandler.DEFAULT_HANDLER);
            structsCreated++;
            println(String.format("Created %s and applied to %d functions (param %d)", structName, funcs.size(), key.paramIndex+1));
        }

        println(String.format("Scanned %d functions. Created %d structs. Updated %d parameters.", funcsScanned, structsCreated, paramsTyped));
    }
}

