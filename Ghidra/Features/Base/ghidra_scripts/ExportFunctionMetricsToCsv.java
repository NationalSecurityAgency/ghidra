/* ###
 * IP: GHIDRA
 * REVIEWED: NO
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
// Exports per-function metrics to a CSV file for the current program.
//@category Functions

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.Msg;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;

public class ExportFunctionMetricsToCsv extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No current program.");
            return;
        }

        File outFile = askFile("Choose output CSV file", "Save");
        if (outFile == null) {
            printerr("No output file selected.");
            return;
        }

        AddressSetView scope = currentSelection != null ? currentSelection : currentHighlight;
        writeFunctionMetricsCsv(currentProgram, outFile, scope);
        println("Wrote function metrics to: " + outFile.getAbsolutePath());
    }

    private void writeFunctionMetricsCsv(Program program, File outFile, AddressSetView scope)
            throws IOException {
        FunctionManager fm = program.getFunctionManager();
        Listing listing = program.getListing();
        CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

        try (BufferedWriter w = new BufferedWriter(new FileWriter(outFile))) {
            // header
            w.write(String.join(",",
                "name","entry","address_ranges","instruction_count","cyclomatic_complexity",
                "parameters","locals","basic_blocks","external","thunk","thunk_target",
                "variadic","inline","no_return","custom_storage","stack_purge_size",
                "calling_convention","namespace","return_type","prototype","prototype_with_cc",
                "callers","callees"));
            w.write("\n");

            FunctionIterator it = fm.getFunctions(true);
            monitor.initialize(fm.getFunctionCount());

            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                AddressSetView body = f.getBody();
                if (scope != null && !scope.intersects(body)) {
                    continue;
                }

                monitor.setMessage("Exporting metrics: " + f.getName());
                monitor.incrementProgress(1);

                String entry = f.getEntryPoint().toString();

                // instruction count
                int instCount = 0;
                for (Iterator<Instruction> insIt = listing.getInstructions(body, true); insIt.hasNext();) {
                    insIt.next();
                    instCount++;
                }

                int callers = sizeSafe(f.getCallingFunctions(monitor));
                int callees = sizeSafe(f.getCalledFunctions(monitor));

                int cplx = 0;
                try {
                    cplx = complexityCalc.calculateCyclomaticComplexity(f, monitor);
                }
                catch (Exception e) {
                    Msg.warn(this, "Failed to compute complexity for " + f.getName(), e);
                }

                int params = f.getParameterCount();

                // basic blocks
                int basicBlocks = 0;
                try {
                    SimpleBlockModel model = new SimpleBlockModel(program);
                    CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
                    while (blocks.hasNext() && !monitor.isCancelled()) {
                        blocks.next();
                        basicBlocks++;
                    }
                }
                catch (CancelledException ce) {
                    // respect cancellation
                }

                int localsCount = 0;
                try {
                    if (!f.isExternal()) {
                        localsCount = f.getLocalVariables().length;
                    }
                }
                catch (Exception ignore) {
                }

                boolean isExternal = f.isExternal();
                boolean isThunk = f.isThunk();
                boolean hasVarArgs = f.hasVarArgs();
                boolean isInline = f.isInline();
                boolean noReturn = f.hasNoReturn();
                boolean customStorage = f.hasCustomVariableStorage();
                int stackPurgeSize = f.getStackPurgeSize();
                String callConv = safeString(f.getCallingConventionName());
                Namespace ns = f.getParentNamespace();
                String namespace = ns != null ? ns.getName(true) : "";
                DataType retType = f.getReturnType();
                String returnType = retType != null ? retType.getDisplayName() : "void";
                String proto = f.getPrototypeString(true, false);
                String protoWithCc = f.getPrototypeString(true, true);
                String thunkTarget = null;
                if (isThunk) {
                    Function tf = f.getThunkedFunction(true);
                    if (tf != null) {
                        thunkTarget = tf.getEntryPoint().toString();
                    }
                }

                w.write(String.join(",",
                    csv(f.getName()), csv(entry),
                    Integer.toString(body.getNumAddressRanges()),
                    Integer.toString(instCount), Integer.toString(cplx),
                    Integer.toString(params), Integer.toString(localsCount),
                    Integer.toString(basicBlocks), Boolean.toString(isExternal),
                    Boolean.toString(isThunk), csvOrEmpty(thunkTarget),
                    Boolean.toString(hasVarArgs), Boolean.toString(isInline),
                    Boolean.toString(noReturn), Boolean.toString(customStorage),
                    Integer.toString(stackPurgeSize), csv(callConv), csv(namespace),
                    csv(returnType), csv(proto), csv(protoWithCc),
                    Integer.toString(callers), Integer.toString(callees)));
                w.write("\n");
            }
        }
    }

    private static int sizeSafe(Set<?> s) {
        return s == null ? 0 : s.size();
    }

    private static String safeString(String s) {
        return s == null ? "" : s;
    }

    private static String csv(String s) {
        if (s == null) {
            return "\"\"";
        }
        String v = s.replace("\"", "\"\"");
        return "\"" + v + "\"";
    }

    private static String csvOrEmpty(String s) {
        return s == null ? "" : csv(s);
    }
}

