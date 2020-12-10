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
package agent.dbgmodel.dbgmodel.concept;

import com.sun.jna.Pointer;

import agent.dbgmodel.dbgmodel.main.ModelObject;

/**
 * A wrapper for {@code IIndexableConcept} and its newer variants.
 */
public interface IndexableConcept extends Concept {

	long getDimensionality(ModelObject contextObject);

	ModelObject getAt(ModelObject contextObject, long indexerCount, Pointer[] indexers);

}
