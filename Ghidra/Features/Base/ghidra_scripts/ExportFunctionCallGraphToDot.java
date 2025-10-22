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
// Exports the program's function call graph to a DOT file.
//@category Graph

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

public class ExportFunctionCallGraphToDot extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No current program.");
            return;
        }

        File outFile = askFile("Choose output DOT file", "Save");
        if (outFile == null) {
            printerr("No output file selected.");
            return;
        }

        AddressSetView scope = currentSelection != null ? currentSelection : currentHighlight;
        writeCallGraphDot(currentProgram, outFile, scope);
        println("Wrote function call graph to: " + outFile.getAbsolutePath());
    }

    private void writeCallGraphDot(Program program, File outFile, AddressSetView scope)
            throws IOException {
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);

        Map<String, Integer> idByEntry = new HashMap<>();
        Set<String> edges = new HashSet<>();
        int nextId = 1;

        monitor.initialize(fm.getFunctionCount());

        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (scope != null && !scope.intersects(f.getBody())) {
                continue;
            }
            monitor.setMessage("Indexing function: " + f.getName());
            monitor.incrementProgress(1);

            String fEntry = f.getEntryPoint().toString();
            idByEntry.computeIfAbsent(fEntry, k -> nextId++);

            for (Function callee : f.getCalledFunctions(monitor)) {
                if (scope != null && !scope.intersects(callee.getBody())) {
                    // If filtered by selection, only keep edges entirely in scope
                    continue;
                }
                String cEntry = callee.getEntryPoint().toString();
                idByEntry.computeIfAbsent(cEntry, k -> nextId++);
                edges.add(fEntry + "->" + cEntry);
            }
        }

        try (BufferedWriter w = new BufferedWriter(new FileWriter(outFile))) {
            String graphName = sanitizeId(program.getName());
            w.write("digraph \"" + escape(program.getName()) + "\" {\n");
            w.write("  node [shape=box, fontsize=10];\n");

            for (Map.Entry<String, Integer> e : idByEntry.entrySet()) {
                String entry = e.getKey();
                int id = e.getValue();
                // label: function name + entry
                Function f = fm.getFunctionAt(program.getAddressFactory().getAddress(entry));
                String label = (f != null ? f.getName() : entry) + "\\n" + entry;
                w.write("  n" + id + " [label=\"" + escape(label) + "\"];\n");
            }

            for (String edge : edges) {
                String[] parts = edge.split("->", 2);
                Integer sId = idByEntry.get(parts[0]);
                Integer tId = idByEntry.get(parts[1]);
                if (sId != null && tId != null) {
                    w.write("  n" + sId + " -> n" + tId + ";\n");
                }
            }

            w.write("}\n");
        }
    }

    private static String sanitizeId(String s) {
        if (s == null || s.isEmpty()) return "G";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_') b.append(c);
        }
        if (b.length() == 0) b.append('G');
        return b.toString();
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}

