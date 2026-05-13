/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.decompiler.parallel;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.concurrent.GThreadPool;

/**
 * Unit coverage for the bounded decompiler worker pool. Full semantic old-vs-new equality is
 * exercised by the companion headless integration script ParallelDecompileBenchmark.java because it
 * requires a real Program and native decompiler process.
 */
public class ParallelDecompilerProcessCountTest {

	@Test
	public void testDefaultProcessCount() {
		String oldValue = System.getProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY);
		try {
			System.clearProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY);
			assertEquals(27, ParallelDecompiler.getDefaultDecompilerProcessCount());
		}
		finally {
			restoreProperty(oldValue);
		}
	}

	@Test
	public void testDefaultProcessCountPropertyOverride() {
		String oldValue = System.getProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY);
		try {
			System.setProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY, "5");
			assertEquals(5, ParallelDecompiler.getDefaultDecompilerProcessCount());
		}
		finally {
			restoreProperty(oldValue);
		}
	}

	@Test
	public void testDefaultProcessCountRejectsInvalidProperty() {
		String oldValue = System.getProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY);
		try {
			System.setProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY, "not-a-number");
			assertEquals(27, ParallelDecompiler.getDefaultDecompilerProcessCount());
		}
		finally {
			restoreProperty(oldValue);
		}
	}

	@Test
	public void testCreatesBoundedPrivateThreadPool() {
		GThreadPool pool = ParallelDecompiler.createBoundedThreadPool(2);
		try {
			assertEquals(2, pool.getMaxThreadCount());
			assertEquals(0, pool.getMinThreadCount());
		}
		finally {
			pool.shutdownNow();
		}
	}

	@Test
	public void testRejectsInvalidProcessCount() {
		try {
			ParallelDecompiler.createBoundedThreadPool(0);
			fail("Expected IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			// expected
		}
	}

	private void restoreProperty(String oldValue) {
		if (oldValue == null) {
			System.clearProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY);
		}
		else {
			System.setProperty(ParallelDecompiler.DECOMPILER_PROCESSES_PROPERTY, oldValue);
		}
	}
}
