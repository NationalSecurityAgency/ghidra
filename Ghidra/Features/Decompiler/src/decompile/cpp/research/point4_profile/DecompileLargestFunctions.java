import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileLargestFunctions extends GhidraScript {
  @Override protected void run() throws Exception {
    String[] argv = getScriptArgs();
    int maxFunctions = argv.length > 0 ? Integer.parseInt(argv[0]) : 30;
    int timeout = argv.length > 1 ? Integer.parseInt(argv[1]) : 60;
    List<Function> funcs = new ArrayList<>();
    for (Function f: currentProgram.getFunctionManager().getFunctions(true)) {
      if (!f.isThunk()) funcs.add(f);
    }
    funcs.sort((a,b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
    DecompileOptions opts = new DecompileOptions();
    opts.grabFromProgram(currentProgram);
    DecompInterface ifc = new DecompInterface();
    ifc.setOptions(opts);
    ifc.openProgram(currentProgram);
    int count=0, ok=0, fail=0;
    long all0=System.nanoTime();
    for (Function f: funcs) {
      if (count>=maxFunctions) break;
      monitor.checkCancelled();
      long t0=System.nanoTime();
      DecompileResults r=ifc.decompileFunction(f, timeout, monitor);
      long ms=(System.nanoTime()-t0)/1000000L;
      boolean completed = r != null && r.decompileCompleted();
      if (completed) ok++; else fail++;
      println("FUNC_PROFILE idx="+count+" entry="+f.getEntryPoint()+" size="+f.getBody().getNumAddresses()+" name="+f.getName(true)+" completed="+completed+" ms="+ms+" err="+(r==null?"null":r.getErrorMessage()));
      count++;
    }
    long allMs=(System.nanoTime()-all0)/1000000L;
    println("FUNC_PROFILE_DONE funcs="+count+" ok="+ok+" fail="+fail+" elapsedMs="+allMs);
    ifc.dispose();
  }
}
