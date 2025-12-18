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
package ghidra.program.model.lang.protorules;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.XmlPullParser;

/**
 * An action that happens during parameter allocation.  It sees resource usage for
 * both input and output parameters and can make changes.  It can act either right after
 * output parameter assignment or after input parameter assignment.
 */
public abstract class SharedAction {
	protected PrototypeModel model;		// The model owning/performing this action

	public SharedAction(PrototypeModel model) {
		this.model = model;
	}

	/**
	 * Implement resource sharing between the input and output parameter assignments.
	 * Called once before input parameters have been assigned (after output assignment).
	 * @param proto is the list of data-types
	 * @param dtManager is the data-type manager
	 * @param addAutoParams is true if the this pointer and other auto-params should be added
	 * @param params is the current set of allocated parameters
	 * @param inputStatus is the consume status for this (input resources)
	 * @param outputStatus is the consume status for output resources
	 */
	public abstract void applyBefore(PrototypePieces proto, DataTypeManager dtManager,
			boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus);

	/**
	 * Implement resource sharing after input and output parameter assignments.
	 * Called once after both input and output parameters have been assigned.
	 * @param proto is the list of data-types
	 * @param dtManager is the data-type manager
	 * @param addAutoParams is true if the this pointer and other auto-params should be added
	 * @param params is the current set of allocated parameters
	 * @param inputStatus is the consume status for this (input resources)
	 * @param outputStatus is the consume status for output resources
	 */
	public abstract void applyAfter(PrototypePieces proto, DataTypeManager dtManager,
			boolean addAutoParams,
			ArrayList<ParameterPieces> params, int[] inputStatus, int[] outputStatus);

	/**
	 * Clone this action onto a new prototype model
	 * @param newModel is the new model
	 * @return the cloned action
	 */
	public abstract SharedAction clone(PrototypeModel newModel);

	public abstract boolean isEquivalent(SharedAction obj);

	public abstract void encode(Encoder encoder) throws IOException;

	public abstract void restoreXml(XmlPullParser parser);
}
