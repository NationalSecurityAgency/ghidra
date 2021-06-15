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
package ghidra.framework.plugintool.mgr;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.data.DummyDomainObject;
import ghidra.framework.model.*;
import ghidra.test.DummyTool;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.TaskMonitor;

public class BackgroundCommandTaskTest extends AbstractGenericTest {

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testSuccessfulCommand() throws Exception {

		DummyTool tool = new DummyTool();
		ToolTaskManager taskManager = new ToolTaskManager(tool);
		SpyDomainObject domainObject = new SpyDomainObject(this);
		SuccessfulDummyCommand cmd = new SuccessfulDummyCommand();
		taskManager.executeCommand(cmd, domainObject);

		waitFor(taskManager);
		assertTrue(domainObject.wasCommitted());
	}

	@Test
	public void testExceptionalCommand_NonRollbackException() throws Exception {

		DummyTool tool = new DummyTool();
		ToolTaskManager taskManager = new ToolTaskManager(tool);
		SpyDomainObject domainObject = new SpyDomainObject(this);
		NullPointerExceptionCommand cmd = new NullPointerExceptionCommand();

		setErrorsExpected(true);
		taskManager.executeCommand(cmd, domainObject);
		waitFor(taskManager);
		setErrorsExpected(false);

		assertTrue(domainObject.wasCommitted());
	}

	@Test
	public void testExceptionalCommand_RollbackException() throws Exception {

		DummyTool tool = new DummyTool();
		ToolTaskManager taskManager = new ToolTaskManager(tool);
		SpyDomainObject domainObject = new SpyDomainObject(this);
		RollbackExceptionCommand cmd = new RollbackExceptionCommand();

		setErrorsExpected(true);
		taskManager.executeCommand(cmd, domainObject);
		waitFor(taskManager);
		setErrorsExpected(false);

		assertFalse(domainObject.wasCommitted());
	}

	@Test
	public void testExceptionalCommand_DomainObjectLockedException() throws Exception {

		DummyTool tool = new DummyTool();
		ToolTaskManager taskManager = new ToolTaskManager(tool);
		SpyDomainObject domainObject = new SpyDomainObject(this);
		DomainObjectLockedExceptionCommand cmd = new DomainObjectLockedExceptionCommand();

		setErrorsExpected(true);
		taskManager.executeCommand(cmd, domainObject);
		waitFor(taskManager);
		setErrorsExpected(false);

		assertFalse(domainObject.wasCommitted());
	}

	private void waitFor(ToolTaskManager taskManager) {
		waitFor(() -> !taskManager.isBusy());
	}

	private class SpyDomainObject extends DummyDomainObject {

		private static final int ID = 1;
		private boolean transactionCommited;

		protected SpyDomainObject(Object consumer) throws IOException {
			super(consumer);
		}

		@Override
		public int startTransaction(String description) {
			return startTransaction(description, null);
		}

		@Override
		public int startTransaction(String description, AbortedTransactionListener listener) {
			return ID;
		}

		@Override
		public void endTransaction(int transactionID, boolean commit) {

			assertEquals(ID, transactionID);
			transactionCommited = commit;
		}

		boolean wasCommitted() {
			return transactionCommited;
		}
	}

	private class SuccessfulDummyCommand extends BackgroundCommand {

		SuccessfulDummyCommand() {
			super("Dummy", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			return true;
		}

	}

	private class NullPointerExceptionCommand extends BackgroundCommand {

		NullPointerExceptionCommand() {
			super("Dummy", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			throw new NullPointerException();
		}

	}

	private class RollbackExceptionCommand extends BackgroundCommand {
		RollbackExceptionCommand() {
			super("Dummy", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			throw new RollbackException("This is a rollback exception");
		}
	}

	private class DomainObjectLockedExceptionCommand extends BackgroundCommand {
		DomainObjectLockedExceptionCommand() {
			super("Dummy", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			throw new DomainObjectLockedException("Unable to connect");
		}
	}
}
