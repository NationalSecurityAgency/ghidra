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
package ghidra.app.util.viewer.field;

import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL FieldMouseHandlerExtension CLASSES MUST END IN "FieldMouseHandler".  If not,
 * the ClassSearcher will not find them.
 * 
 * An interface to signal that it can handle mouse clicks for registered objects.  To register 
 * the handler you need to return the class that the handler supports in the class array 
 * returned from {@link #getSupportedProgramLocations()}.
 * <p>
 * New handlers are automatically picked-up by Ghidra upon startup via the 
 * {@link ClassSearcher} mechanism.
 * 
 * @see FieldNavigator
 */
public interface FieldMouseHandlerExtension extends FieldMouseHandler, ExtensionPoint {
    
}
