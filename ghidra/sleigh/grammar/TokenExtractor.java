/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.sleigh.grammar;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TokenExtractor {
    public static void main(String[] args) {
        try {
            final int numberParams = 4;
            File baseInPath = new File(args[0]);
            File baseOutPath = new File(args[1]);
            String packedge = args[2];
            String name = args[3];
            File outputFile = new File(baseOutPath, name + ".g");
            File[] inFiles = new File[args.length - numberParams];
            for (int ii = 0; ii < inFiles.length; ++ii) {
                inFiles[ii] = new File(baseInPath, args[ii + numberParams]);
            }
            HashSet<String> set = extract(inFiles);
            write(packedge, name, outputFile, set);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void write(String packedge, String name, File outputFile, HashSet<String> set)
            throws IOException {
        PrintWriter out = null;
        try {
            if (!outputFile.getParentFile().exists()) {
                outputFile.getParentFile().mkdirs();
            }
        	System.out.println("writing tokens to: " + outputFile.getCanonicalPath());
            out = new PrintWriter(outputFile);
            out.println("lexer grammar " + name + ";");
            if (packedge != null && !packedge.trim().equals("")) {
                out.println("@lexer::header{");
                out.println("package " + packedge + ";");
                out.println("}");
            }
            int ii = 4;
            for (String s : set) {
                out.format("%s: '%04d';", s, ii);
                out.println();
                ++ii;
            }
        }
        finally {
            if (out != null) {
                out.close();
            }
        }
    }

    private static Pattern P1 = Pattern.compile("^\\s*([A-Z_][A-Z_0-9]*)\\s*$");
    private static Pattern P2 = Pattern.compile("^\\s*([A-Z_][A-Z_0-9]*)\\s*;");
    private static Pattern P3 = Pattern.compile("^\\s*([A-Z_][A-Z_0-9]*)\\s*=");
    private static Pattern P4 = Pattern.compile("^\\s*([A-Z_][A-Z_0-9]*)\\s*:");

    private static void match(Matcher m, HashSet<String> set) {
        if (m.find()) {
            set.add(m.group(1));
        }
    }

    private static HashSet<String> extract(File[] inFiles) throws IOException {
        HashSet<String> result = new HashSet<String>();
        BufferedReader in = null;
        for (int ii = 0; ii < inFiles.length; ++ii) {
        	System.out.println("extracting tokens from: " + inFiles[ii].getCanonicalPath());
            try {
                in = new BufferedReader(new FileReader(inFiles[ii]));
                String line;
                while ((line = in.readLine()) != null) {
                    match(P1.matcher(line), result);
                    match(P2.matcher(line), result);
                    match(P3.matcher(line), result);
                    match(P4.matcher(line), result);
                }
            }
            finally {
                if (in != null) {
                    in.close();
                }
            }
        }
        return result;
    }
}
