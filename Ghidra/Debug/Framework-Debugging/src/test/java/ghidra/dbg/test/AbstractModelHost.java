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
package ghidra.dbg.test;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.testutil.*;
import ghidra.dbg.testutil.TestDebuggerModelProvider.ModelHost;
import ghidra.dbg.util.*;
import ghidra.dbg.util.ConfigurableFactory.Property;
import ghidra.dbg.util.PathUtils.PathComparator;

public abstract class AbstractModelHost implements ModelHost, DebuggerModelTestUtils {

	public class WithoutThreadValidationImpl implements WithoutThreadValidation {
		public WithoutThreadValidationImpl() {
			withoutThreadValCount++;
		}

		@Override
		public void close() throws Exception {
			withoutThreadValCount--;
		}
	}

	private int withoutThreadValCount = 0;

	protected DebuggerObjectModel model;
	public CallbackValidator callbackValidator;
	public EventValidator eventValidator;
	public TargetObjectAddedWaiter waiter;
	public DebuggerConsole console;

	protected boolean validateCallbacks = true;
	// NB. GDB's modules actually aren't "unloaded" until the inferior's file is replaced
	protected boolean validateEvents = false;
	protected boolean provideConsole = true;

	@Override
	public DebuggerObjectModel buildModel(Map<String, Object> options) throws Throwable {
		DebuggerModelFactory factory = getModelFactory();
		for (Map.Entry<String, Object> opt : options.entrySet()) {
			@SuppressWarnings("unchecked")
			Property<Object> property = (Property<Object>) factory.getOptions().get(opt.getKey());
			property.setValue(opt.getValue());
		}
		DebuggerObjectModel model = waitOn(factory.build());
		if (validateCallbacks) {
			callbackValidator = new CallbackValidator(model);
		}
		if (validateEvents) {
			eventValidator = new EventValidator(model);
		}
		if (provideConsole) {
			console = new DebuggerConsole(model);
		}
		waiter = new TargetObjectAddedWaiter(model);
		return model;
	}

	@Override
	public AbstractModelHost build() throws Throwable {
		model = buildModel(getFactoryOptions());
		return this;
	}

	@Override
	public DebuggerObjectModel getModel() {
		return model;
	}

	@Override
	public void validateCompletionThread() {
		if (callbackValidator != null && withoutThreadValCount == 0) {
			callbackValidator.validateCompletionThread();
		}
	}

	@Override
	public TargetObject getRoot() throws Throwable {
		// Nothing waits on root unless they call this. Cannot use getModelRoot()
		return waitOn(model.fetchModelRoot());
	}

	@Override
	public void close() throws Exception {
		if (model != null) {
			try {
				waitOn(model.close());
			}
			catch (Exception e) {
				throw e;
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		}
		if (callbackValidator != null) {
			callbackValidator.close();
		}
		if (eventValidator != null) {
			eventValidator.close();
		}
		if (console != null) {
			console.close();
		}
		if (waiter != null) {
			waiter.close();
		}
	}

	public abstract DebuggerModelFactory getModelFactory();

	@Override
	public List<String> getBogusPath() {
		return PathUtils.parse("THIS.PATH[SHOULD].NEVER[EXIST]");
	}

	@Override
	public boolean hasDetachableProcesses() {
		return true;
	}

	@Override
	public boolean hasInterpreter() {
		return true;
	}

	@Override
	public boolean hasInterruptibleProcesses() {
		return true;
	}

	@Override
	public boolean hasKillableProcesses() {
		return true;
	}

	@Override
	public boolean hasResumableProcesses() {
		return true;
	}

	@Override
	public boolean hasAttachableContainer() {
		return true;
	}

	@Override
	public boolean hasAttacher() {
		return true;
	}

	@Override
	public boolean hasEventScope() {
		return true;
	}

	@Override
	public boolean hasLauncher() {
		return true;
	}

	@Override
	public boolean hasProcessContainer() {
		return true;
	}

	@Override
	public WithoutThreadValidation withoutThreadValidation() {
		return new WithoutThreadValidationImpl();
	}

	@Override
	public TargetObjectAddedWaiter getAddedWaiter() {
		return waiter;
	}

	@Override
	public <T extends TargetObject> T find(Class<T> cls, List<String> seedPath) throws Throwable {
		PathMatcher matcher =
			model.getRootSchema().getSuccessorSchema(seedPath).searchFor(cls, seedPath, true);
		if (matcher.isEmpty()) {
			return null;
		}
		return cls.cast(assertUniqueShortest(waitOn(waiter.waitAtLeastOne(matcher))));
	}

	@Override
	public <T extends TargetObject> T findWithIndex(Class<T> cls, String index,
			List<String> seedPath) throws Throwable {
		Objects.requireNonNull(index); // Use find if no index is expected
		PathPredicates matcher = model.getRootSchema()
				.getSuccessorSchema(seedPath)
				.searchFor(cls, seedPath, true)
				.applyIndices(index);
		if (matcher.isEmpty()) {
			return null;
		}
		return cls.cast(waitOn(waiter.wait(matcher.getSingletonPath())));
	}

	@Override
	public <T extends TargetObject> T findAny(Class<T> cls, List<String> seedPath)
			throws Throwable {
		PathMatcher matcher =
			model.getRootSchema().getSuccessorSchema(seedPath).searchFor(cls, seedPath, true);
		if (matcher.isEmpty()) {
			return null;
		}
		return cls.cast(waitOn(waiter.waitAtLeastOne(matcher)).firstEntry().getValue());
	}

	@Override
	public <T extends TargetObject> NavigableMap<List<String>, T> findAll(Class<T> cls,
			List<String> seedPath, boolean atLeastOne) throws Throwable {
		return findAll(cls, seedPath, pred -> pred, atLeastOne);
	}

	@Override
	public <T extends TargetObject> NavigableMap<List<String>, T> findAll(Class<T> cls,
			List<String> seedPath, Function<PathPredicates, PathPredicates> adjustPredicates,
			boolean atLeastOne) throws Throwable {
		PathPredicates matcher = adjustPredicates.apply(model.getRootSchema()
				.getSuccessorSchema(seedPath)
				.searchFor(cls, seedPath, false));
		if (matcher.isEmpty()) {
			return new TreeMap<>();
		}

		NavigableMap<List<String>, ?> found = atLeastOne
				? waitOn(waiter.waitAtLeastOne(matcher))
				: matcher.getCachedValues(model.getModelRoot());
		// NB. Outside of testing, an "unsafe" cast of the map should be fine.
		// During testing, we should expend the energy to verify the heap.
		NavigableMap<List<String>, T> result = new TreeMap<>(PathComparator.KEYED);
		for (Entry<List<String>, ?> ent : found.entrySet()) {
			//TODO GP-1301
			if (cls.isInstance(ent.getValue())) {
				result.put(ent.getKey(), cls.cast(ent.getValue()));
			}
		}
		return result;
	}

	@Override
	public TargetObject findContainer(Class<? extends TargetObject> cls, List<String> seedPath)
			throws Throwable {
		List<String> foundSub =
			model.getRootSchema().getSuccessorSchema(seedPath).searchForCanonicalContainer(cls);
		if (foundSub == null) {
			return null;
		}
		List<String> path = PathUtils.extend(seedPath, foundSub);
		return (TargetObject) waitOn(waiter.wait(path));
	}

	@Override
	public <T extends TargetObject> T suitable(Class<T> cls, List<String> seedPath)
			throws Throwable {
		List<String> path = model.getRootSchema().searchForSuitable(cls, seedPath);
		if (path == null) {
			return null;
		}
		return cls.cast(waitOn(waiter.wait(path)));
	}
}
