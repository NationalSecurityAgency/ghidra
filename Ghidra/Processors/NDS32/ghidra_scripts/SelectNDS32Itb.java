//@category NDS32
//@menupath Analysis.NDS32.Select ITB
// Interactive helper for picking which ITB value to use when multiple
// mtusr,itb writers are detected.  Sets the "ITB override (hex)" analyzer
// option to the chosen value and re-runs the NDS32 ITB / EX9IT analyzer.
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

public class SelectNDS32Itb extends GhidraScript {
    @Override
    public void run() throws Exception {
        Register itbReg = currentProgram.getLanguage().getRegister("itb");
        if (itbReg == null) {
            popup("This program's language does not define an 'itb' register.");
            return;
        }

        Map<Long, Address> candidates = discoverCandidates(currentProgram);
        if (candidates.isEmpty()) {
            popup("No mtusr,itb writers found.  You can still set " +
                "an ITB manually in the analyzer options.");
            return;
        }

        // Build choice strings.
        List<String> choices = new ArrayList<>();
        List<Long> choiceVals = new ArrayList<>();
        for (Map.Entry<Long, Address> e : candidates.entrySet()) {
            choices.add(String.format("0x%08x  (first set at %s)",
                e.getKey(), e.getValue()));
            choiceVals.add(e.getKey());
        }
        choices.add("Clear override -- use automatic selection");
        choiceVals.add(null);

        String picked = askChoice("Select ITB", "Choose which ITB value should drive ex9.it decoding:",
            choices, choices.get(0));
        if (picked == null) return;

        int idx = choices.indexOf(picked);
        Long chosen = choiceVals.get(idx);

        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        String name = "NDS32 ITB / EX9IT.ITB override (hex)";
        opts.setString(name, chosen == null ? "" : String.format("0x%x", chosen));
        println(chosen == null
            ? "Cleared manual ITB override; analyzer will auto-select."
            : String.format("Set manual ITB override to 0x%x", chosen));

        // Re-run the analyzer immediately.
        try {
            Class<?> klass = Class.forName(
                "ghidra.app.plugin.core.analysis.NDS32ITBAnalyzer");
            Object analyzer = klass.getDeclaredConstructor().newInstance();
            Method added = klass.getMethod("added",
                Program.class,
                ghidra.program.model.address.AddressSetView.class,
                ghidra.util.task.TaskMonitor.class,
                MessageLog.class);
            MessageLog log = new MessageLog();
            added.invoke(analyzer, currentProgram, currentProgram.getMemory(), monitor, log);
            println("Analyzer re-run.  Log:\n" + log.toString());
        }
        catch (Exception e) {
            println("Failed to re-run analyzer: " + e.getMessage()
                + " (the option is still set; auto-analysis will pick it up next time).");
        }
    }

    private static Map<Long, Address> discoverCandidates(Program program) {
        Listing listing = program.getListing();
        Map<Long, Address> out = new LinkedHashMap<>();
        for (Instruction in : listing.getInstructions(true)) {
            if (!in.getMnemonicString().equalsIgnoreCase("mtusr")) continue;
            Register r1 = in.getRegister(1);
            if (r1 == null || !r1.getName().equalsIgnoreCase("itb")) continue;
            BigInteger v = traceConstant(in);
            if (v == null) continue;
            Long key = v.longValue();
            if (!out.containsKey(key)) out.put(key, in.getAddress());
        }
        return out;
    }

    // Simplified trace -- same logic as NDS32ITBAnalyzer.traceConstantWrittenToFirstOperand.
    private static BigInteger traceConstant(Instruction mtusrInsn) {
        Register src = mtusrInsn.getRegister(0);
        if (src == null) return null;
        long hi = -1, lo = -1;
        Instruction cur = mtusrInsn.getPrevious();
        for (int i = 0; cur != null && i < 16; cur = cur.getPrevious(), i++) {
            String m = cur.getMnemonicString().toLowerCase();
            Register dst = cur.getRegister(0);
            if (dst == null || !dst.equals(src)) continue;
            if (m.equals("movi")) {
                Scalar s = cur.getScalar(1);
                if (s == null) return null;
                return BigInteger.valueOf(s.getSignedValue() & 0xffffffffL);
            }
            if (m.equals("ori")) {
                Scalar s = cur.getScalar(2);
                if (s == null) return null;
                lo = s.getUnsignedValue();
                continue;
            }
            if (m.equals("sethi")) {
                Scalar s = cur.getScalar(1);
                if (s == null) return null;
                hi = s.getUnsignedValue() << 12;
                break;
            }
            return null;
        }
        if (hi == -1) return null;
        long val = hi | (lo == -1 ? 0 : lo);
        return BigInteger.valueOf(val & 0xffffffffL);
    }
}
