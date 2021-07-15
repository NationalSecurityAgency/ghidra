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
package ghidra.plugin.importer;

/**
 * Language/Compiler selection table event listener interface.
 */
public interface LcsSelectionListener {

    /**
     * Event types enumeration.
     */
    enum EventType {
        /**
         * The selected value has changed.
         */
        VALUE_CHANGED,

        /**
         * The currently selected value was chosen.
         */
        VALUE_CHOSEN
    }

    /**
     * The selected value in the language/compiler selection table has changed.
     *
     * @param e the selection event.
     */
    void valueChanged(LcsSelectionEvent e);

    /**
     * The currently selected value in the language/compiler selection table was chosen for further operations.
     *
     * @param e the selection event.
     */
    void valueChosen(LcsSelectionEvent e);
}
