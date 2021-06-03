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
package ghidra.app.plugin.core.functioncompare;

import java.util.List;

import ghidra.app.services.FunctionComparisonModel;

/**
 * Allows subscribers to register for {@link FunctionComparisonModel function
 * comparison model} changes
 */
public interface FunctionComparisonModelListener {

	/**
	 * Invoked when the comparison model has changed
	 * 
	 * @param model the current state of the model
	 */
	public void modelChanged(List<FunctionComparison> model);
}
