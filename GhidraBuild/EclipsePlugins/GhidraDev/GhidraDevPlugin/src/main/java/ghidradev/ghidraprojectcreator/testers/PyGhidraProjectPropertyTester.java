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
package ghidradev.ghidraprojectcreator.testers;

import javax.naming.OperationNotSupportedException;

import org.eclipse.core.expressions.PropertyTester;

import ghidradev.ghidraprojectcreator.utils.GhidraProjectUtils;
import ghidradev.ghidraprojectcreator.utils.PyDevUtils;

/**
 * A {@link PropertyTester} used to determine if a given Eclipse resource is part
 * of a PyGhidra project.
 */
public class PyGhidraProjectPropertyTester extends PropertyTester {

	@Override
	public boolean test(Object receiver, String property, Object[] args, Object expectedValue) {
		try {
			return PyDevUtils.isPyGhidraProject(GhidraProjectUtils.getEnclosingProject(receiver));
		}
		catch (OperationNotSupportedException e) {
			return false;
		}
	}
}
