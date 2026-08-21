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
package generic.test.rule;

import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import generic.test.AbstractGenericTest;

/**
 * A test rule which processes the {@link IgnoreUnfinished} annotation
 * 
 * <p>
 * This must be included in your test case (or a superclass) as a field with the {@link Rule}
 * annotation. It's included in the {@link AbstractGenericTest}, so most Ghidra test classes already
 * have it.
 */
public class IgnoreUnfinishedRule implements TestRule {
	@Override
	public Statement apply(Statement base, Description description) {
		IgnoreUnfinished annot;
		annot = description.getAnnotation(IgnoreUnfinished.class);
		if (annot != null) {
			return new IgnoreUnfinishedStatement(base);
		}
		annot = description.getTestClass().getAnnotation(IgnoreUnfinished.class);
		if (annot != null) {
			return new IgnoreUnfinishedStatement(base);
		}
		return base;
	}
}
