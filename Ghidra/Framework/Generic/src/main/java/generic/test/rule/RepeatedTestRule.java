/* ###
 * IP: Apache License 2.0
 */
package generic.test.rule;

import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import generic.test.AbstractGenericTest;

/**
 * A test rule which processes the {@link Repeated} annotation
 * 
 * <p>
 * This must be included in your test case (or a superclass) as a field with the {@link Rule}
 * annotation. It's included in {@link AbstractGenericTest}, so most Ghidra test classes already
 * have it.
 */
public class RepeatedTestRule implements TestRule {
	@Override
	public Statement apply(Statement base, Description description) {
		Repeated annot = description.getAnnotation(Repeated.class);
		if (annot == null) {
			return base;
		}
		return new RepeatedStatement(base, description, annot.value());
	}
}
