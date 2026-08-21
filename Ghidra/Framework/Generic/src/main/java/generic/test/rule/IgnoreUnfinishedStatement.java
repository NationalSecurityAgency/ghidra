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

import org.junit.AssumptionViolatedException;
import org.junit.runners.model.Statement;

import ghidra.lifecycle.Unfinished.TODOException;

/**
 * A JUnit test statement that ignores {@link TODOException}
 * 
 * @see IgnoreUnfinished
 */
public class IgnoreUnfinishedStatement extends Statement {
	private final Statement base;

	public IgnoreUnfinishedStatement(Statement base) {
		this.base = base;
	}

	@Override
	public void evaluate() throws Throwable {
		try {
			base.evaluate();
		}
		catch (TODOException e) {
			throw new AssumptionViolatedException("Unfinished", e);
		}
	}
}
