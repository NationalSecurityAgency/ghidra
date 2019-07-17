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
package ghidra.app.util.datatype;

import ghidra.program.model.data.Composite;
import ghidra.util.exception.UsrException;

/**
 * Exception thrown if the composite data type is empty.
 * Typically this will be thrown if the user tries to save or apply a
 * composite with no components.
 */
public class EmptyCompositeException extends UsrException {

    /**
     * Constructor.
     */
    public EmptyCompositeException() {
        super("Data type is empty.");
    }

    /**
     * Constructor
     * @param composite the structure data type that is empty.
     */
    public EmptyCompositeException(Composite composite) {
        super(composite.getDisplayName() + " is empty.");
    }

    /**
     * Constructor
     * @param message detailed message explaining exception
     */
    public EmptyCompositeException(String message) {
        super(message);
    }
}
