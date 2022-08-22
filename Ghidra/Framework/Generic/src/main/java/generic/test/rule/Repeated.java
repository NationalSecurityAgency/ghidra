/* ###
 * IP: Apache License 2.0
 */
package generic.test.rule;

import java.lang.annotation.*;

/**
 * Repeat the annotated test method some number of times
 * 
 * <p>
 * As a matter of practice, no test should ever be committed into source control with this
 * annotation. It is only a tool for diagnosing non-deterministic test failures on the developer's
 * workstation. For example, suppose {@code testSomeMethod} fails every other Tuesday on the CI
 * system, but never seems to fail on the developer's workstation. It might help to repeat a test
 * 100 times, including its set-up and tear-down, in a single test run. To do this, the developer
 * can temporarily add the {@code @Repeated(100)} annotation, and then run the test from their IDE.
 * 
 * <pre>
 * &#64;Test
 * &#64;Repeated(100)
 * public void testSomeMethod() {
 * 	SomeClass obj = new SomeClass();
 * 	obj.someMethod();
 * 	assertEquals(3, obj.getSomeState());
 * }
 * </pre>
 * 
 * <p>
 * The number of repetitions can be adjusted depending on the desired level of assurance. If the
 * failure is truly due to timing, and not some other condition unique to the CI system, then it
 * will likely fail within 100 repetitions. Once the code is fixed, and the test passes for the
 * desired number of repetitions, the annotation should be removed before the changes are committed.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Repeated {
	/**
	 * The number of times to repeat the test, must be positive
	 * 
	 * @return the count
	 */
	int value();
}
