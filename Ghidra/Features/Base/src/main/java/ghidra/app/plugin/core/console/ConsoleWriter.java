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
package ghidra.app.plugin.core.console;

import ghidra.app.services.ConsoleService;

import java.io.IOException;
import java.io.Writer;

class ConsoleWriter extends Writer {
    private ConsoleService console;
    private boolean error;

    ConsoleWriter(ConsoleService console, boolean error) {
        super();
        this.console = console;
        this.error = error;
    }

    /**
     * @see java.io.Writer#close()
     */
    @Override
    public void close() throws IOException {
        console.clearMessages();
    }

    /**
     * @see java.io.Writer#flush()
     */
    @Override
    public void flush() throws IOException {
    }

    /**
     * @see java.io.Writer#write(char[], int, int)
     */
    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        String str = new String(cbuf, off, len);
        if (error) {
            console.printError(str);
        }
        else {
            console.print(str);
        }
    }
}
