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
package ghidra.trace.model.target.annot;

import java.lang.annotation.*;

import ghidra.dbg.target.TargetObject;
import ghidra.trace.model.target.TraceObjectManager;

/**
 * Information about a trace target interface
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface TraceObjectInfo {
	/**
	 * The target interface corresponding to this trace interface
	 * 
	 * <p>
	 * TODO: I really don't like this here. I would rather the schema interface names were mappable
	 * to a chosen domain, rather than being fixed on {@link TargetObject}.... In any case, this is
	 * used to ensure that {@link TraceObjectManager#queryAllInterface(Class)} and related have a
	 * means of translating from the trace domain into the target domain.
	 */
	Class<? extends TargetObject> targetIf();

	/**
	 * A short name for this interface type
	 */
	String shortName();

	/**
	 * Keys intrinsic to this interface, whose values are fixed during the object's lifespan
	 */
	String[] fixedKeys();
}
