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

import org.antlr.runtime.CharStream;
import org.antlr.runtime.CommonToken;
import org.antlr.runtime.Token;

public class SleighToken extends CommonToken {
    private Location location;

    public SleighToken(CharStream input, int type, int channel, int start,
            int stop) {
        super(input, type, channel, start, stop);
    }

    public SleighToken(int type, String text) {
        super(type, text);
    }

    public SleighToken(int type) {
        super(type);
    }

    public SleighToken(int type, int line, int charPos) {
        super(type);
        this.line = line;
        this.charPositionInLine = charPos;
    }

    public SleighToken(Token oldToken) {
        super(oldToken);
    }

    @Override
    public String toString() {
        return super.toString() + "@" + location;
    }

    public Location getLocation() {
        return location;
    }

    public void setLocation(Location location) {
        this.location = location;
    }
}
