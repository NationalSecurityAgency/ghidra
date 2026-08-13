<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="xml" indent="yes"/>
    <xsl:strip-space elements="*"/>
    
    <xsl:param name="fileName" />
    <xsl:variable name="updates" select="document($fileName)" />

    
    <xsl:template match="@* | node()">
        <xsl:copy>
            <xsl:apply-templates select="@* | node()"/>
        </xsl:copy>
    </xsl:template>

    <!-- 1. Schema Level: Merging Children -->
    <xsl:template match="schema">
        <xsl:variable name="schemaName" select="@name"/>
        <xsl:variable name="updateSchema" select="$updates/context/schema[@name = $schemaName]"/>
        
        <xsl:copy>
            <xsl:apply-templates select="@*"/>
            <!-- Process File 1 children -->
            <xsl:apply-templates select="node()"/>
            
            <!-- Add children from File 2 that are completely missing in File 1 -->
            <xsl:if test="$updateSchema">
                <xsl:variable name="file1Children" select="*"/>
                <xsl:for-each select="$updateSchema/*">
                    <xsl:choose>
                        <!-- For nodes with names -->
                        <xsl:when test="@name and not($file1Children[@name = current()/@name])">
                            <xsl:copy-of select="."/>
                        </xsl:when>
                        <!-- For nodes without names (e.g. VOID) match by schema -->
                        <xsl:when test="not(@name) and @schema and not($file1Children[not(@name) and @schema = current()/@schema])">
                            <xsl:copy-of select="."/>
                        </xsl:when>
                        <!-- For nodes without names (e.g. VOID) match by 'from' -->
                        <xsl:when test="not(@name) and @from and not($file1Children[not(@name) and @from = current()/@from])">
                            <xsl:copy-of select="."/>
                        </xsl:when>
                    </xsl:choose>
                </xsl:for-each>
            </xsl:if>
        </xsl:copy>
    </xsl:template>

    <!-- 2. Overwrite Rule for attributes WITH a name -->
    <xsl:template match="schema/*[@name]">
        <xsl:variable name="schemaName" select="../@name"/>
        <xsl:variable name="childName" select="@name"/>
        <xsl:variable name="updateNode" select="$updates/context/schema[@name = $schemaName]/*[@name = $childName]"/>
        
        <xsl:choose>
            <xsl:when test="$updateNode">
                <xsl:copy-of select="$updateNode"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:copy><xsl:apply-templates select="@* | node()"/></xsl:copy>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <!-- 3. Overwrite Rule for attributes WITHOUT a name (VOID, ANY) -->
    <xsl:template match="schema/*[not(@name) and @schema]">
        <xsl:variable name="schemaName" select="../@name"/>
        <xsl:variable name="schemaType" select="@schema"/>
        <xsl:variable name="updateNode" select="$updates/context/schema[@name = $schemaName]/*[not(@name) and @schema = $schemaType]"/>
        
        <xsl:choose>
            <xsl:when test="$updateNode">
                <xsl:copy-of select="$updateNode"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:copy><xsl:apply-templates select="@* | node()"/></xsl:copy>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <!-- 4. Add completely new schemas -->
    <xsl:template match="/*">
        <xsl:copy>
            <xsl:apply-templates select="@* | node()"/>
            <xsl:variable name="file1Root" select="."/>
            <xsl:for-each select="$updates/context/schema">
                <xsl:if test="not($file1Root/schema[@name = current()/@name])">
                    <xsl:copy-of select="."/>
                </xsl:if>
            </xsl:for-each>
        </xsl:copy>
    </xsl:template>
    
</xsl:stylesheet>
