/* ###
* IP: GHIDRA
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

package ghidra.util;

import java.util.ArrayList;

public class SkipManager implements Skipper {
    ArrayList<Skipper> skippers;
    private static SkipManager inst;
    private SkipManager() {
        this.skippers = new ArrayList<Skipper>();
    }

    public static SkipManager getInstance() {
        if(inst == null) {
            inst = new SkipManager();
        }
        return inst;
    }

    public void registerSkipper(Skipper s) {
        this.skippers.add(s);
    }

    @Override
    public boolean shouldSkip(String functionName) {
        return this.skippers.stream().anyMatch(skipper -> skipper.shouldSkip(functionName));
    }

    @Override
    public boolean shouldSkip(long addr) {
        return this.skippers.stream().anyMatch(skipper -> skipper.shouldSkip(addr));
    }
}
