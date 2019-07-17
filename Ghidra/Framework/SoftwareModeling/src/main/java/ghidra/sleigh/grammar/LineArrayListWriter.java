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

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;

public class LineArrayListWriter extends Writer {

    protected ArrayList<StringBuilder> lines = new ArrayList<StringBuilder>();
    protected int lineno = 0;

    public LineArrayListWriter() {
        newLine();
    }

    public void newLine() {
        lineno++;
        lines.add(new StringBuilder());
    }

    @Override
    public void close() throws IOException {
    // do nothing; the writer never actually closes
    }

    @Override
    public void flush() throws IOException {
    // do nothing; the writer always flushes all the time
    }

    protected static final String LINE_SEPARATOR = System.getProperty("line.separator");

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        String input = new String(cbuf, off, len);
        lines.get(lineno - 1).append(input);
    }

    public ArrayList<String> getLines() {
        ArrayList<String> result = new ArrayList<String>();
        for (StringBuilder sb : lines) {
            result.add(sb.toString());
        }
        return result;
    }

    @Override
    public String toString() {
        StringBuilder acc = new StringBuilder();
        for (StringBuilder sb : lines) {
            acc.append(sb);
            acc.append(LINE_SEPARATOR);
        }
        return acc.toString();
    }
}
