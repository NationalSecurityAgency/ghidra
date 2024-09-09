package ghidra.pyhidra;

import org.junit.Test;

import ghidra.pyhidra.PythonFieldExposer.ExposedField;

import static org.junit.Assert.assertTrue;

import java.util.Map;;

public class PythonFieldExposerTest {

    @Test
    public void test() {
        Map<String, ExposedField> fields = PythonFieldExposer.getProperties(PyhidraScriptProvider.PyhidraGhidraScript.class);
        assertTrue(fields.containsKey("currentProgram"));
    }
}
