package ghidra.app.util.bin.format.stabs;

import java.io.IOException;
import java.util.List;

import org.junit.Test;

public class StabsFullCTest extends AbstractStabsTest {

	public StabsFullCTest() {
		super();
	}

	@Override
	protected List<String> getStabs() throws IOException {
		return loadTextResource(StabsFullCTest.class, "full_c_stabs.txt");
	}

	@Test
	public void parseTest() throws Exception {
		// test complete
	}
}
