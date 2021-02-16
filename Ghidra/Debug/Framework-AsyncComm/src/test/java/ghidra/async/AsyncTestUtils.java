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
package ghidra.async;

import java.util.concurrent.*;

import ghidra.util.SystemUtilities;

public interface AsyncTestUtils {
	static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	default <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (Exception e) {
			throw AsyncUtils.unwrapThrowable(e);
		}
	}

	default void waitOn(Executor executor) throws Throwable {
		waitOn(CompletableFuture.supplyAsync(() -> null, executor));
	}
}
