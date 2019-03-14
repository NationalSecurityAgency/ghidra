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
package ghidra.util.prop;

import ghidra.util.Saveable;

/**
 * PropertyVisitor is an interface for use with user defined 
 * properties when you know the name of the property but not its
 * type. 
 */

public interface PropertyVisitor {
    /** Handle the case of a void property type. */
    void visit();
    /** Handle the case of a String property type. */
    void visit(String value);
    /** Handle the case of an Object property type. */
    void visit(Object value);
    /** Handle the case of a Saveable property type*/
    void visit(Saveable value);
    /** Handle the case of an int property type. */
    void visit(int value);
}
