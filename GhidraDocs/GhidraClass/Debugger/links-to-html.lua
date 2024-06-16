-- https://stackoverflow.com/questions/40993488/convert-markdown-links-to-html-with-pandoc
function Link(el)
  el.target = string.gsub(el.target, "%.md", ".html")
  return el
end

