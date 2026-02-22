import test from "node:test";
import assert from "node:assert/strict";

import { renderMarkdown } from "../src/index.js";

test("renderMarkdown supports common blocks", () => {
  const html = renderMarkdown(`# 標題

- 第一項
- 第二項
1. 一
2. 二

---
> 引用
`);

  assert.match(html, /<h1>標題<\/h1>/);
  assert.match(html, /<ul><li>第一項<\/li><li>第二項<\/li><\/ul>/);
  assert.match(html, /<ol><li>一<\/li><li>二<\/li><\/ol>/);
  assert.match(html, /<hr \/>/);
  assert.match(html, /<blockquote>引用<\/blockquote>/);
});

test("renderMarkdown escapes html and supports inline syntax", () => {
  const html = renderMarkdown("**粗體** *斜體* ~~刪除~~ `<script>`");
  assert.match(html, /<strong>粗體<\/strong>/);
  assert.match(html, /<em>斜體<\/em>/);
  assert.match(html, /<del>刪除<\/del>/);
  assert.match(html, /<code>&lt;script&gt;<\/code>/);
});

test("renderMarkdown keeps line breaks and preserves math delimiters", () => {
  const html = renderMarkdown(`第一行
第二行

行內公式 $a^2+b^2=c^2$

$$
\\int_0^1 x^2 \\, dx
$$`);

  assert.match(html, /第一行<br \/>第二行/);
  assert.match(html, /\$a\^2\+b\^2=c\^2\$/);
  assert.match(html, /<div class="math-block">\\\[/);
});
