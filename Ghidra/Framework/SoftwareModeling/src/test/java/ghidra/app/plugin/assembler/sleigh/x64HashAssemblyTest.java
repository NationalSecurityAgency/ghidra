package ghidra.app.plugin.assembler.sleigh;

import org.junit.Test;

import ghidra.program.model.lang.LanguageID;

public class x64HashAssemblyTest extends AbstractAssemblyTest {

    @Override
    protected LanguageID getLanguageID() {
        return new LanguageID("x86:LE:64:default");
    }

    @Test
    public void testAssemble_VSHA512MSG1_YMM1_XMM0() {
        assertOneCompatRestExact("VSHA512MSG1 YMM1,XMM0", "c4:e2:7f:cc:c8");
    }

    @Test
    public void testAssemble_VSHA512MSG2_YMM1_YMM0() {
        assertOneCompatRestExact("VSHA512MSG2 YMM1,YMM0", "c4:e2:7f:cd:c8");
    }

    @Test
    public void testAssemble_VSHA512RNDS2_YMM2_YMM1_XMM0() {
        assertOneCompatRestExact("VSHA512RNDS2 YMM2,YMM1,XMM0", "c4:e2:77:cb:d0");
    }

    @Test
    public void testAssemble_VSM3MSG1_XMM2_XMM1_XMM0() {
        assertOneCompatRestExact("VSM3MSG1 XMM2,XMM1,XMM0", "c4:e2:70:da:d0");
    }

    @Test
    public void testAssemble_VSM3MSG2_XMM2_XMM1_XMM0() {
        assertOneCompatRestExact("VSM3MSG2 XMM2,XMM1,XMM0", "c4:e2:71:da:d0");
    }

    @Test
    public void testAssemble_VSM3RNDS2_XMM3_XMM2_XMM1_0x0() {
        assertOneCompatRestExact("VSM3RNDS2 XMM3,XMM2,XMM1,0x0", "c4:e3:69:de:d9:00");
    }

    @Test
    public void testAssemble_VSM4KEY4_XMM2_XMM1_XMM0() {
        assertOneCompatRestExact("VSM4KEY4 XMM2,XMM1,XMM0", "c4:e2:72:da:d0");
    }

    @Test
    public void testAssemble_VSM4RNDS4_XMM2_XMM1_XMM0() {
        assertOneCompatRestExact("VSM4RNDS4 XMM2,XMM1,XMM0", "c4:e2:73:da:d0");
    }

    @Test
    public void testAssemble_VSM4KEY4_XMM22_XMM21_XMM20() {
        assertOneCompatRestExact("VSM4KEY4 XMM22,XMM21,XMM20", "62:a2:56:00:da:f4");
    }

    @Test
    public void testAssemble_VSM4KEY4_YMM22_YMM21_YMM20() {
        assertOneCompatRestExact("VSM4KEY4 YMM22,YMM21,YMM20", "62:a2:56:20:da:f4");
    }

    @Test
    public void testAssemble_VSM4KEY4_ZMM22_ZMM21_ZMM20() {
        assertOneCompatRestExact("VSM4KEY4 ZMM22,ZMM21,ZMM20", "62:a2:56:40:da:f4");
    }

    @Test
    public void testAssemble_VSM4KEY4_XMM22_mRAX() {
        assertOneCompatRestExact("VSM4KEY4 XMM22,XMM21,xmmword ptr [RAX]", "62:e2:56:00:da:30");
    }

    @Test
    public void testAssemble_VSM4KEY4_YMM22_mRAX() {
        assertOneCompatRestExact("VSM4KEY4 YMM22,YMM21,ymmword ptr [RAX]", "62:e2:56:20:da:30");
    }

    @Test
    public void testAssemble_VSM4KEY4_ZMM22_mRAX() {
        assertOneCompatRestExact("VSM4KEY4 ZMM22,ZMM21,zmmword ptr [RAX]", "62:e2:56:40:da:30");
    }

    @Test
    public void testAssemble_VSM4RNDS4_XMM22_XMM21_XMM20() {
        assertOneCompatRestExact("VSM4RNDS4 XMM22,XMM21,XMM20", "62:a2:57:00:da:f4");
    }

    @Test
    public void testAssemble_VSM4RNDS4_YMM22_YMM21_YMM20() {
        assertOneCompatRestExact("VSM4RNDS4 YMM22,YMM21,YMM20", "62:a2:57:20:da:f4");
    }

    @Test
    public void testAssemble_VSM4RNDS4_ZMM22_ZMM21_ZMM20() {
        assertOneCompatRestExact("VSM4RNDS4 ZMM22,ZMM21,ZMM20", "62:a2:57:40:da:f4");
    }

    @Test
    public void testAssemble_VSM4RNDS4_XMM22_mRAX() {
        assertOneCompatRestExact("VSM4RNDS4 XMM22,XMM21,xmmword ptr [RAX]", "62:e2:57:00:da:30");
    }

    @Test
    public void testAssemble_VSM4RNDS4_YMM22_mRAX() {
        assertOneCompatRestExact("VSM4RNDS4 YMM22,YMM21,ymmword ptr [RAX]", "62:e2:57:20:da:30");
    }

    @Test
    public void testAssemble_VSM4RNDS4_ZMM22_mRAX() {
        assertOneCompatRestExact("VSM4RNDS4 ZMM22,ZMM21,zmmword ptr [RAX]", "62:e2:57:40:da:30");
    }
}