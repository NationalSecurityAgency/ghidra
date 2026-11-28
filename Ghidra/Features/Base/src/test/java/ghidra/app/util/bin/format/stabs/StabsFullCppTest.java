package ghidra.app.util.bin.format.stabs;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

public class StabsFullCppTest extends AbstractStabsTest {

	public StabsFullCppTest() {
		super();
	}

	@Override
	protected List<String> getStabs() throws IOException {
		return loadTextResource(StabsFullCppTest.class, "full_cpp_stabs.txt");
	}

	@Test
	public void parseTest() throws Exception {
		// test complete
	}
}
