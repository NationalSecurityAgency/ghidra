<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:param name="generate.toc">
    article/appendix  nop
    article   title,toc
    book      toc,title,figure,table,example,equation
    chapter   nop
    part      toc,title
    preface   toc,title
    qandadiv  toc
    qandaset  toc
    reference toc,title
    sect1     nop
    sect2     nop
    sect3     nop
    sect4     nop
    sect5     nop
    section   nop
    set       toc,title
  </xsl:param>

  <!-- Where does the title go, relative to the object -->
  <xsl:param name="formal.title.placement">
    figure after
    example before
    equation before
    table before
    procedure before
    task before
  </xsl:param>

  <!-- Automatically number sections -->
  <xsl:param name="section.autolabel" select="1"/>

</xsl:stylesheet>
