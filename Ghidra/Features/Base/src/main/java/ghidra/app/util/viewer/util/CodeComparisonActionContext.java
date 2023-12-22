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
package ghidra.app.util.viewer.util;

import java.awt.Component;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import ghidra.program.model.listing.Function;

public abstract class CodeComparisonActionContext extends DefaultActionContext
		implements CodeComparisonPanelActionContext {
	/** 
	 * Constructor with no source component and no context object
	 * @param provider the ComponentProvider that generated this context.
	 */
	public CodeComparisonActionContext(ComponentProvider provider) {
		super(provider);
	}

	/**
	 * Constructor with source component and context object
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param contextObject an optional contextObject that the ComponentProvider can provide; this 
	 *        can be anything that actions wish to later retrieve
	 * @param sourceComponent an optional source object; this is intended to be the component that
	 *        is the source of the context, usually the focused component
	 */
	public CodeComparisonActionContext(ComponentProvider provider, Object contextObject,
			Component sourceComponent) {
		super(provider, contextObject, sourceComponent);
	}

	/**
	 * Returns the function that is the source of the info being applied. This will be whichever
	 * side of the function diff window that isn't active. 
	 * @return the function to get information from
	 */
	public abstract Function getSourceFunction();

	/**
	 * Returns the function that is the target of the info being applied. This will be whichever
	 * side of the function diff window that is active.
	 * @return the function to apply information to
	 */
	public abstract Function getTargetFunction();

}
