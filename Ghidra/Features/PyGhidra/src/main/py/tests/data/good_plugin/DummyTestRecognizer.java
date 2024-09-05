package ghidra.pyghidra.test;

import ghidra.app.util.recognizer.Recognizer;

/**
 * Simple ExtensionPoint class for PyGhidra plugin test.
 * 
 * This can be any ExtensionPoint. Recognizer was chosen here
 * because it has a small number of methods and hasn't changed in a long time.
 */
public class DummyTestRecognizer implements Recognizer {
    
    // simple static field we can reach and check for a pytest
    // normally this would be an interface implemented in Python
    // that would be set so this class can call into Python
    public static boolean preLaunchInitialized = false;
    
    @Override
    public int getPriority() {
        return 0;
    }
    
    @Override
    public int numberOfBytesRequired() {
        return 0;
    }
    
    @Override
    public String recognize(byte[] bytes) {
        return "";
    }
}
