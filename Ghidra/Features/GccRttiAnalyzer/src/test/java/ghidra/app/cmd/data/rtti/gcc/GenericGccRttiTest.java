package ghidra.app.cmd.data.rtti.gcc;

import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

import org.junit.Before;

import generic.test.AbstractGenericTest;

public class GenericGccRttiTest extends AbstractGenericTest {

	protected GenericGccRttiTest() {
		super();
	}

	@Before
	public void setup() throws Exception {
		ClassSearcher.search(true, TaskMonitor.DUMMY);
	}
}
