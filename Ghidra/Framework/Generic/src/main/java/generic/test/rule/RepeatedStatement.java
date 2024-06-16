/* ###
 * IP: Apache License 2.0
 */
package generic.test.rule;

import java.util.Date;

import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import ghidra.util.Msg;

/**
 * A JUnit test statement that repeats its base statement 1 or more times
 * 
 * @see Repeated
 */
public class RepeatedStatement extends Statement {
	private final Statement base;
	private final Description description;
	private final int count;

	/**
	 * Construct the statement
	 * 
	 * @param base the base statement to repeat
	 * @param description the description of the test
	 * @param count the number of repetitions, must be positive
	 */
	public RepeatedStatement(Statement base, Description description, int count) {
		if (count <= 0) {
			throw new IllegalArgumentException(
				"@Repeated count must be positive. To ignore a test. Use @Ignore");
		}
		this.base = base;
		this.description = description;
		this.count = count;
	}

	@Override
	public void evaluate() throws Throwable {
		for (int i = 0; i < count; i++) {
			if (count > 1) {
				Msg.debug(this,
					(new Date()) + "\n  *** REPETITION " + (i + 1) + "/" + count + " of " +
						description.getDisplayName() + " ***");
			}
			base.evaluate();
		}
	}
}
