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
package utility.function;

import java.util.function.Consumer;

/**
 * TerminatingConsumer is a Consumer {@link Consumer} that can request termination
 * of the supplier once some condition is reached, for example some number of consumed results
 * accepted.  If termination is required override the terminationRequested()
 * method to return true when termination state is reached.
 *
 * @param <T> the type of the input to the operation
 */
public interface TerminatingConsumer<T> extends Consumer<T> {

    default boolean terminationRequested() {
        return false;
    }
}
