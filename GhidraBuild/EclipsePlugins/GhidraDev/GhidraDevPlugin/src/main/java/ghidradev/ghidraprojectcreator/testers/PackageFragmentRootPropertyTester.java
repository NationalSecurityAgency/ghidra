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

import java.util.List;

import org.eclipse.core.expressions.PropertyTester;
import org.eclipse.jdt.core.IPackageFragmentRoot;

/**
 * A {@link PropertyTester} used to determine if a given Eclipse resource is a Java package 
 * fragment root (which is basically a Java source folder on the build path).
 */
public class PackageFragmentRootPropertyTester extends PropertyTester {

	@Override
	public boolean test(Object receiver, String property, Object[] args, Object expectedValue) {

		if (receiver instanceof List) {
			List<?> list = (List<?>) receiver;
			if (list.size() == 1) {
				receiver = list.iterator().next();
			}
		}

		return receiver instanceof IPackageFragmentRoot;
	}
}
