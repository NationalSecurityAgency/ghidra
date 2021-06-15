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
package mdemangler;

import org.junit.experimental.categories.Categories;
import org.junit.experimental.categories.Categories.ExcludeCategory;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Categories.class)
@ExcludeCategory(MDMangFailingTestCategory.class)
@SuiteClasses(MDMangBaseTest.class)
/**
 * This test suite has the purpose of driving the tests in MDMangBaseTest and
 * only testing those that are known not to be failing at this time. Failing
 * tests exist because I have not yet crafted an effective way to deal with them
 * yet that does not also cause other tests to fail... or they might be failing
 * for other reasons that I will not get into here. Essentially this suite
 * exists for the purpose of providing a suite of tests that will not fail
 * during nightly or continuous testing. The MDMangBaseTest class is not located
 * in a folder that will be seen by these tests.
 */
public class MDMangBaseWorkingTests {
	// Purposefully empty.
}
