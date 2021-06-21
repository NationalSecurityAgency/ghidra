<?xml version='1.0'?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl"/>

<xsl:param name="generate.toc">
  article/appendix  nop
  article   toc,title
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

<xsl:param name="use.id.as.filename" select="1"/>  <!-- Split up into files based on id attribute -->

<xsl:param name="html.stylesheet" select="'Frontpage.css'"/>    <!-- Use our custom cascading style sheet -->

<xsl:param name="chunker.output.indent" select="'yes'"/>  <!-- Do proper indenting of html -->

</xsl:stylesheet>
