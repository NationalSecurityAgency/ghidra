package ghidra.app.util.bin.format.pdb;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;

public class CategoryBuildingTest extends AbstractGhidraHeadlessIntegrationTest {

    @Test
    public void parsingStructureNameWithoutNamespace() throws Exception {
        var parser = createParser();
        var symbolName = "variable";
        var categoryPath = parser.getCategory(symbolName, false);
        var typeName = parser.stripNamespace(symbolName);

        assertNotNull("Category path should be not null", categoryPath);
        assertEquals("/", categoryPath.getPath());
        assertEquals("variable", typeName);
    }

    @Test
    public void parsingSimpleStructureName() throws Exception {
        var parser = createParser();
        var symbolName = "prefs::kHomePageChanged";
        var categoryPath = parser.getCategory(symbolName, false);
        var typeName = parser.stripNamespace(symbolName);

        assertNotNull("Category path should be not null", categoryPath);
        assertEquals("/prefs", categoryPath.getPath());
        assertEquals("kHomePageChanged", typeName);
    }

    @Test
    public void parsingStructureNameWithinMultipleNamespaces() throws Exception {
        var parser = createParser();
        var symbolName = "policy::key::kImportHomepage";
        var categoryPath = parser.getCategory(symbolName, false);
        var typeName = parser.stripNamespace(symbolName);

        assertNotNull("Category path should be not null", categoryPath);
        assertEquals("/policy/key", categoryPath.getPath());
        assertEquals("kImportHomepage", typeName);
    }

    @Test
    public void parsingComplexNames() throws Exception {
        var parser = createParser();
        var symbolName = "std::_Vector_const_iterator<std::_Vector_val<base::Value *,std::allocator<base::Value *> > >";
        var categoryPath = parser.getCategory(symbolName, false);
        var typeName = parser.stripNamespace(symbolName);

        assertNotNull("Category path should be not null", categoryPath);
        assertEquals("/std", categoryPath.getPath());
        assertEquals("_Vector_const_iterator<std::_Vector_val<base::Value *,std::allocator<base::Value *> > >", typeName);
    }

    @Test
    public void parsingCliArray() throws Exception {
        var parser = createParser();
        var symbolName = "namespace::ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>";
        var categoryPath = parser.getCategory(symbolName, false);
        var typeName = parser.stripNamespace(symbolName);

        assertNotNull("Category path should be not null", categoryPath);
        assertEquals("/namespace", categoryPath.getPath());
        assertEquals("ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>", typeName);
    }

    private PdbParserNEW createParser() {
        var file = new File("test.pdb.xml");
        var parser = new PdbParserNEW(file, null, null, null,false);
        return parser;
    }
}
