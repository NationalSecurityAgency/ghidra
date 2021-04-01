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
package ghidra.dbg.model;

import java.io.IOException;
import java.util.concurrent.*;

import org.jdom.JDOMException;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;

// TODO: Refactor with other Fake and Test model stuff.
public class TestDebuggerObjectModel extends EmptyDebuggerObjectModel {
	public static final String TEST_MODEL_STRING = "Test Model";
	protected static final int DELAY_MILLIS = 250;

	// TODO: Should this be tunable?
	public static final Executor DELAYED_EXECUTOR =
		CompletableFuture.delayedExecutor(DELAY_MILLIS, TimeUnit.MILLISECONDS);

	enum FutureMode {
		ASYNC, DELAYED;
	}

	public static final XmlSchemaContext SCHEMA_CTX;
	public static final TargetObjectSchema ROOT_SCHEMA;
	static {
		try {
			SCHEMA_CTX = XmlSchemaContext.deserialize(
				EmptyDebuggerObjectModel.class.getResourceAsStream("test_schema.xml"));
			ROOT_SCHEMA = SCHEMA_CTX.getSchema(SCHEMA_CTX.name("Test"));
		}
		catch (IOException | JDOMException e) {
			throw new AssertionError(e);
		}
	}

	public final TestTargetSession session;

	protected int invalidateCachesCount;

	public TestDebuggerObjectModel() {
		this("Session");
	}

	public Executor getClientExecutor() {
		return clientExecutor;
	}

	public TestDebuggerObjectModel(String rootHint) {
		this.session = new TestTargetSession(this, rootHint, ROOT_SCHEMA);
		addModelRoot(session);
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		return ROOT_SCHEMA;
	}

	@Override
	public String toString() {
		return TEST_MODEL_STRING;
	}

	@Override // TODO: Give test writer control of addModelRoot
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return future(session);
	}

	@Override
	public CompletableFuture<Void> close() {
		session.invalidateSubtree(session, "Model closed");
		return future(null).thenCompose(__ -> super.close());
	}

	public TestTargetProcess addProcess(int pid) {
		return session.addProcess(pid);
	}

	public <T> CompletableFuture<T> future(T t) {
		return CompletableFuture.supplyAsync(() -> t, getClientExecutor());
	}

	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		return session.requestFocus(obj);
	}

	@Override
	public synchronized void invalidateAllLocalCaches() {
		invalidateCachesCount++;
	}

	public synchronized int clearInvalidateCachesCount() {
		int result = invalidateCachesCount;
		invalidateCachesCount = 0;
		return result;
	}
}
