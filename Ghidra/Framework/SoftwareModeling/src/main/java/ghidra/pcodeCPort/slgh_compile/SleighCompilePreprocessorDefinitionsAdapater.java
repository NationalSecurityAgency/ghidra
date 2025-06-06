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
package ghidra.pcodeCPort.slgh_compile;

import generic.stl.Pair;

public class SleighCompilePreprocessorDefinitionsAdapater implements
        PreprocessorDefinitions {

    private final SleighCompile sleighCompile;

    public SleighCompilePreprocessorDefinitionsAdapater(SleighCompile sleighCompile) {
        this.sleighCompile = sleighCompile;
    }

    @Override
	public Pair<Boolean, String> lookup(String key) {
        return sleighCompile.getPreprocValue(key);
    }

    @Override
	public void set(String key, String value) {
        sleighCompile.setPreprocValue(key, value);
    }

    @Override
	public void undefine(String key) {
        sleighCompile.undefinePreprocValue(key);
    }
}
