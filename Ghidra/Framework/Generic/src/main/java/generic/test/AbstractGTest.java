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
package generic.test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TestName;

import ghidra.framework.Application;
import ghidra.framework.TestApplicationUtils;
import ghidra.util.SystemUtilities;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.AssertException;
import junit.framework.AssertionFailedError;

/**
 * A root for system tests that provides known system information.
 *
 * <P>This class exists so that fast unit tests have a place to share data without having the
 * slowness of more heavy weight concepts like {@link Application}, logging, etc.
 *
 * <P>						!!	WARNING  !!
 * This test is meant to initialize quickly.  All file I/O should be avoided.
 */
public abstract class AbstractGTest {

	static {
		// Ensure that UniversalIDGenerator is initialized
		UniversalIdGenerator.initialize();
	}

	public final static boolean BATCH_MODE = SystemUtilities.isInTestingBatchMode();
	protected final static boolean PARALLEL_MODE = Boolean.parseBoolean(
		System.getProperty("ghidra.test.property.parallel.mode", Boolean.FALSE.toString()));

	// currently set to 200ms in parallel mode; we can increase as needed; too long slows tests
	public static final int DEFAULT_WAIT_DELAY = 10 * (PARALLEL_MODE ? 20 : 1);
	public static final int DEFAULT_WAIT_TIMEOUT = 2000 * (PARALLEL_MODE ? 10 : 1);
	public static final int DEFAULT_WINDOW_TIMEOUT = DEFAULT_WAIT_TIMEOUT;

	// Note: these start with PRIVATE in order to discourage direct test usage
	// 5x longer than normal
	protected static final int PRIVATE_LONG_WAIT_TIMEOUT = DEFAULT_WAIT_TIMEOUT * 5;
	// 10x longer than normal
	// private static final int PRIVATE_MAX_WAIT_TIMEOUT = DEFAULT_WAIT_TIMEOUT * 10;

	private static String testDirectoryPath = createTestDirectoryPath();

	@Rule
	public TestName testName = new TestName();

	/**
	 * Get the directory path within which all temporary test
	 * data files should be created.
	 * @return test directory path ending with a File.separator character
	 */
	private static String createTestDirectoryPath() {

		if (testDirectoryPath == null) {

			//
			// Build unique test data directory.  Note that we can't make any calls which
			// depend upon Application initialization, so we have to create directories using
			// knowledge of how our environments are setup.
			//
			if (BATCH_MODE) {
				testDirectoryPath = buildBatchDirectoryPath();
			}
			else {
				testDirectoryPath = buildDevelopmentDirectoryPath();
			}
		}

		File testDir = new File(testDirectoryPath);
		if (!testDir.exists()) {
			if (!testDir.mkdirs()) {
				throw new AssertException("Failed to create temp directory: " + testDir);
			}
			System.out.println("Created test directory: " + testDir);
		}

		return testDirectoryPath;
	}

	private static String buildBatchDirectoryPath() {
		//
		// In batch mode we rely on the fact that the test environment has been setup with a
		// custom temp directory.
		//
		return System.getProperty("java.io.tmpdir") + File.separator + "Ghidra_test_" +
			UUID.randomUUID() + File.separator + "temp.data";
	}

	private static String buildDevelopmentDirectoryPath() {
		//
		// Create a unique name based upon the repo from which we are running.
		//
		File tempDir = TestApplicationUtils.getUniqueTempFolder();
		return tempDir.getAbsolutePath();
	}

	public static String getTestDirectoryPath() {
		return testDirectoryPath;
	}

	public static int getRandomInt() {
		return getRandomInt(0, Integer.MAX_VALUE);
	}

	public static int getRandomInt(int min, int max) {
		int distributionLength = (max - min) + 1;// make inclusive
		double randomValueInRange = Math.random() * distributionLength;
		int randomInt = (int) randomValueInRange;
		int valueInRangeWithOffset = min + randomInt;

		// don't go beyond the max in the case where we hit the boundary above (with the +1)
		return Math.min(valueInRangeWithOffset, max);
	}

	public static String getRandomString() {
		return "STR_" + getRandomString(0, 20);
	}

	public static String getRandomString(int min, int max) {
		int stringLength = getRandomInt(min, max);
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < stringLength; i++) {
			buffy.append((char) getRandomInt(65, 127));
		}
		return buffy.toString();
	}

	/**
	 * Compares the contents of two arrays to determine if they are equal.  The contents must
	 * match in the same order. If <code>message</code>
	 * is <code>null</code>, then a generic error message will be printed.
	 *
	 * @param message The message to print upon failure; can be null
	 * @param expected The expected array.
	 * @param actual The actual array.
	 */
	public static void assertArraysEqualOrdered(String message, Object[] expected,
			Object[] actual) {

		if (expected == null) {
			assertNull(actual);
			return;
		}
		assertListEqualOrdered(message, Arrays.asList(expected), Arrays.asList(actual));
	}

	/**
	 * Compares the contents of two arrays to determine if they are equal.  The contents do not have
	 * to be in the same order.  If <code>message</code>
	 * is <code>null</code>, then a generic error message will be printed.
	 *
	 * @param message The message to print upon failure; can be null
	 * @param expected The expected array.
	 * @param actual The actual array.
	 */
	public static void assertArraysEqualUnordered(String message, Object[] expected,
			Object[] actual) {

		if (expected == null) {
			assertNull(actual);
			return;
		}
		assertListEqualUnordered(null, Arrays.asList(expected), Arrays.asList(actual));
	}

	public static void assertListEqualOrdered(List<?> expected, List<?> actual) {
		assertListEqualOrdered(null, expected, actual);
	}

	public static void assertListEqualOrdered(String message, List<?> expected, List<?> actual) {

		if (expected == null) {
			assertNull(actual);
			return;
		}

		Assert.assertEquals(printListFailureMessage(message, expected, actual), expected.size(),
			actual.size());
		for (int i = 0; i < expected.size(); i++) {
			if (!actual.get(i).equals(expected.get(i))) {
				Assert.fail(printListFailureMessage(message, expected, actual));
			}
		}
	}

	public static void assertListEqualUnordered(String message, List<?> expected, List<?> actual) {

		if (expected == null) {
			assertNull(actual);
			return;
		}

		List<?> expectedCopy = new ArrayList<>(expected);
		List<?> actualCopy = new ArrayList<>(actual);

		actualCopy.removeAll(expected);
		expectedCopy.removeAll(actual);

		if (actualCopy.isEmpty() && expectedCopy.isEmpty()) {
			// all expected items accounted for in the actual values
			return;
		}

		// OK, one or both lists had extra data
		if (message == null) {
			message = "\tExpected collections to be the same; " +
				"one or both collections had extra items - difference:" +
				"\n\n\n\t'Expected' unique values: " + expectedCopy +
				";\n\t'Actual' unique values:      " + actualCopy + "\n\n";
		}
		fail(message);
	}

	@SafeVarargs
	public static <T> void assertListEqualsArrayOrdered(List<T> actual, T... expected) {
		assertListEqualOrdered(null, Arrays.asList(expected), actual);
	}

	public static void assertListEqualsArrayUnordered(List<?> actual, Object... expected) {
		assertListEqualUnordered(null, Arrays.asList(expected), actual);
	}

	/**
	 * Compares the contents of two arrays to determine if they are equal
	 *
	 * @param expected The expected array.
	 * @param actual The actual array.
	 */
	public static void assertArraysEqualUnordered(String[] expected, String[] actual) {
		assertArraysEqualUnordered(null, expected, actual);
	}

	@SafeVarargs
	public static <T> void assertContainsExactly(Collection<T> collection, T... expected) {
		List<T> asList = Arrays.asList(expected);

		Set<T> expectedSet = new HashSet<>(collection);
		Set<T> actualSet = new HashSet<>(asList);

		expectedSet.removeAll(asList);
		actualSet.removeAll(collection);

		if (!actualSet.isEmpty()) {
			Assert.fail("Collection did not contain expected results.\nExpected: " + asList +
				"\nFound: " + collection);
		}
		if (!expectedSet.isEmpty()) {
			Assert.fail("collection also contained extra results: " + expectedSet);
		}
	}

	public static <T> void assertContainsExactly(Collection<T> expected, Collection<T> actual) {

		Set<T> expectedSet = new HashSet<>(expected);
		Set<T> actualSet = new HashSet<>(actual);

		expectedSet.removeAll(actual);
		actualSet.removeAll(expected);

		if (!actualSet.isEmpty()) {
			Assert.fail("Actual collection had more entries than expected.\nExpected: " + expected +
				"\nFound:      " + actual);
		}

		if (!expectedSet.isEmpty()) {
			Assert.fail(
				"Expected collection had these entries not found in the actual collection: " +
					expectedSet);
		}
	}

	private static String printListFailureMessage(String message, List<?> expected,
			List<?> actual) {

		StringBuffer buffer = new StringBuffer();
		buffer.append("Expected: ").append(expected.toString());
		buffer.append(" Found: ").append(actual.toString());
		buffer.toString();

		if (message == null) {
			return buffer.toString();
		}

		return message + "\n\n" + buffer;
	}

	public static void failWithException(String message, Throwable e) {
		AssertionError error = new AssertionError(message);
		error.initCause(e);
		throw error;
	}

	/**
	 * Returns the current test method name
	 *
	 * @return the current test method name
	 */
	public String getName() {
		return testName.getMethodName();
	}

	/**
	 * Friendly way to create an array of bytes with static values.
	 *
	 * @param unsignedBytes var-args list of unsigned byte values (ie. 0..255)
	 * @return array of bytes
	 */
	public static byte[] bytes(int... unsignedBytes) {
		byte[] result = new byte[unsignedBytes.length];
		for (int i = 0; i < unsignedBytes.length; i++) {
			result[i] = (byte) unsignedBytes[i];
		}
		return result;
	}

//==================================================================================================
// Wait Methods
//==================================================================================================

	public static long sleep(long timeMs) {

		long start = System.currentTimeMillis();
		try {
			Thread.sleep(timeMs);
		}
		catch (InterruptedException e) {
			// don't care
		}

		long end = System.currentTimeMillis();
		return end - start;
	}

	/**
	 * Waits for the given latch to be counted-down
	 *
	 * @param latch the latch to await
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitFor(CountDownLatch latch) {
		try {
			if (!latch.await(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS)) {
				throw new AssertionFailedError("Timed-out waiting for CountDownLatch");
			}
		}
		catch (InterruptedException e) {
			fail("Interrupted waiting for CountDownLatch");
		}
	}

	/**
	 * Waits for the given AtomicBoolean to return true.  This is a convenience method for
	 * {@link #waitFor(BooleanSupplier)}.
	 *
	 * @param ab the atomic boolean
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitFor(AtomicBoolean ab) throws AssertionFailedError {
		waitForCondition(() -> ab.get());
	}

	/**
	 * Waits for the given condition to return true
	 *
	 * @param condition the condition that returns true when satisfied
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitFor(BooleanSupplier condition) throws AssertionFailedError {
		waitForCondition(condition);
	}

	/**
	 * Waits for the given condition to return true
	 *
	 * @param condition the condition that returns true when satisfied
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitForCondition(BooleanSupplier condition) throws AssertionFailedError {
		waitForCondition(condition, "Timed-out waiting for condition");
	}

	/**
	 * Waits for the given condition to return true
	 *
	 * @param condition the condition that returns true when satisfied
	 * @param failureMessage the message to print upon the timeout being reached
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitForCondition(BooleanSupplier condition, String failureMessage)
			throws AssertionFailedError {

		waitForCondition(condition, true /*failOnTimeout*/, failureMessage);
	}

	/**
	 * Waits for the given condition to return true
	 *
	 * @param condition the condition that returns true when satisfied
	 * @param failureMessageSupplier the function that will supply the failure message in the
	 *        event of a timeout.
	 * @throws AssertionFailedError if the condition is not met within the timeout period
	 */
	public static void waitForCondition(BooleanSupplier condition,
			Supplier<String> failureMessageSupplier) throws AssertionFailedError {

		waitForCondition(condition, true /*failOnTimeout*/, failureMessageSupplier);
	}

	/**
	 * Waits for the given condition to return true.  Most of the <code>waitForCondition()</code>
	 * methods throw an {@link AssertionFailedError} if the timeout period expires.
	 *  This method allows you to setup a longer wait period by repeatedly calling this method.
	 *
	 * <P>Most clients should use {@link #waitForCondition(BooleanSupplier)}.
	 *
	 * @param supplier the supplier that returns true when satisfied
	 */
	public static void waitForConditionWithoutFailing(BooleanSupplier supplier) {
		waitForCondition(supplier, false /*failOnTimeout*/, () -> null /*failure message*/);
	}

	private static void waitForCondition(BooleanSupplier condition, boolean failOnTimeout,
			String failureMessage) throws AssertionFailedError {

		waitForCondition(condition, failOnTimeout, () -> failureMessage);
	}

	private static void waitForCondition(BooleanSupplier condition, boolean failOnTimeout,
			Supplier<String> failureMessageSupplier) throws AssertionFailedError {

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			if (condition.getAsBoolean()) {
				return; // success
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		if (!failOnTimeout) {
			return;
		}

		String failureMessage = "Timed-out waiting for condition";
		if (failureMessageSupplier != null) {
			failureMessage = failureMessageSupplier.get();
		}

		throw new AssertionFailedError(failureMessage);
	}

	/**
	 * Waits for the value returned by the supplier to be non-null, throwing an exception if
	 * that does not happen by the default timeout.
	 *
	 * @param supplier the supplier of the value
	 * @param failureMessage the message to print upon the timeout being reached
	 * @return the non-null value
	 * @throws AssertionFailedError if a non-null value is not returned within the timeout period
	 */
	public static <T> T waitFor(Supplier<T> supplier, String failureMessage) {
		return waitForValue(supplier, failureMessage, true);
	}

	/**
	 * Waits for the value returned by the supplier to be non-null, throwing an exception if
	 * that does not happen by the default timeout.
	 *
	 * @param supplier the supplier of the value
	 * @return the non-null value
	 * @throws AssertionFailedError if a non-null value is not returned within the timeout period
	 */
	public static <T> T waitFor(Supplier<T> supplier) {
		return waitForValue(supplier);
	}

	/**
	 * Waits for the value returned by the supplier to be non-null, throwing an exception if
	 * that does not happen by the default timeout.
	 *
	 * @param supplier the supplier of the value
	 * @return the non-null value
	 * @throws AssertionFailedError if a non-null value is not returned within the timeout period
	 */
	public static <T> T waitForValue(Supplier<T> supplier) {
		return waitForValue(supplier, null, true /*failOnTimeout*/);
	}

	/**
	 * Waits for the value returned by the supplier to be non-null.  If the timeout period
	 * expires, then null will be returned.   Most of the <code>waitXyz()</code> methods
	 * throw an {@link AssertionFailedError} if the timeout period expires.  This method allows
	 * you to setup a longer wait period by repeatedly calling this method.
	 *
	 * <P>Most clients should use {@link #waitForValue(Supplier)}.
	 *
	 * @param supplier the supplier of the value
	 * @return the value; may be null
	 * @see #waitForValue(Supplier)
	 */
	public static <T> T waitForValueWithoutFailing(Supplier<T> supplier) {
		return waitForValue(supplier, null, false /*failOnTimeout*/);
	}

	/**
	 * Waits for the value returned by the supplier to be non-null, optionally
	 * throwing an exception if that does not happen by the given timeout.
	 *
	 * @param supplier the supplier of the value
	 * @param failureMessage the message to print upon the timeout being reached
	 * @param failOnTimeout if true, an exception will be thrown if the timeout is reached
	 * @return the value
	 * @throws AssertionFailedError if a non-null value is not returned within the timeout period
	 */
	private static <T> T waitForValue(Supplier<T> supplier, String failureMessage,
			boolean failOnTimeout) {
		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			T t = supplier.get();
			if (t != null) {
				return t; // success
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		if (!failOnTimeout) {
			return null;
		}

		String error =
			failureMessage != null ? failureMessage : "Timed-out waiting for non-null value";
		throw new AssertionFailedError(error);
	}

//==================================================================================================
// End Wait Methods
//==================================================================================================
}
