#!/usr/bin/env bun
/**
 * Build script for marketing site
 * Converts Markdown content to HTML with styling
 */

import { readFile, writeFile, readdir, mkdir, stat } from "node:fs/promises";
import { join, dirname, relative } from "node:path";

// Simple Markdown to HTML converter (no external deps)
function markdownToHtml(markdown: string, title: string): string {
  let html = markdown;
  
  // Extract title from first h1 if not provided
  const h1Match = html.match(/^# (.+)$/m);
  const pageTitle = title || (h1Match ? h1Match[1] : "claw.events");
  
  // Convert headers
  html = html.replace(/^###### (.+)$/gm, "<h6>$1</h6>");
  html = html.replace(/^##### (.+)$/gm, "<h5>$1</h5>");
  html = html.replace(/^#### (.+)$/gm, "<h4>$1</h4>");
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");
  
  // Convert code blocks
  html = html.replace(/```bash\n([\s\S]*?)```/g, '<pre class="language-bash"><code>$1</code></pre>');
  html = html.replace(/```json\n([\s\S]*?)```/g, '<pre class="language-json"><code>$1</code></pre>');
  html = html.replace(/```\n([\s\S]*?)```/g, "<pre><code>$1</code></pre>");
  
  // Convert inline code
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  
  // Convert bold and italic
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, "<strong><em>$1</em></strong>");
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.+?)\*/g, "<em>$1</em>");
  
  // Convert links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  
  // Convert tables (simple version)
  const tableRegex = /\|(.+)\|\n\|[-:\| ]+\|\n((?:\|.+\|\n?)+)/g;
  html = html.replace(tableRegex, (match, header, rows) => {
    const headers = header.split("|").map((h: string) => h.trim()).filter(Boolean);
    const headerHtml = headers.map((h: string) => `<th>${h}</th>`).join("");
    
    const bodyRows = rows.trim().split("\n").map((row: string) => {
      const cells = row.split("|").map((c: string) => c.trim()).filter(Boolean);
      return "<tr>" + cells.map((c: string) => `<td>${c}</td>`).join("") + "</tr>";
    }).join("");
    
    return `<table><thead><tr>${headerHtml}</tr></thead><tbody>${bodyRows}</tbody></table>`;
  });
  
  // Convert lists
  html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.+<\/li>\n)+/g, "<ul>$&</ul>");
  
  // Convert numbered lists
  html = html.replace(/^\d+\. (.+)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.+<\/li>\n)+/g, (match) => {
    if (match.startsWith("<ul>")) return match;
    return `<ol>${match}</ol>`;
  });
  
  // Wrap paragraphs
  const lines = html.split("\n");
  let inBlock = false;
  const wrapped = lines.map((line) => {
    if (line.startsWith("<")) {
      inBlock = line.startsWith("<pre") || line.startsWith("<table") || line.startsWith("<ul") || line.startsWith("<ol");
      if (line.startsWith("</pre") || line.startsWith("</table") || line.startsWith("</ul") || line.startsWith("</ol")) {
        inBlock = false;
      }
      return line;
    }
    if (line.trim() === "" || inBlock) return line;
    return `<p>${line}</p>`;
  });
  html = wrapped.join("\n");
  
  // Clean up empty paragraphs
  html = html.replace(/<p><\/p>/g, "");
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${pageTitle} - claw.events</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --bg: #ffffff;
            --text: #1f2937;
            --text-light: #6b7280;
            --border: #e5e7eb;
            --code-bg: #f3f4f6;
        }
        
        * { box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text);
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem 1rem;
            background: var(--bg);
        }
        
        h1 { 
            color: var(--primary); 
            border-bottom: 3px solid var(--primary);
            padding-bottom: 0.5rem;
            margin-top: 0;
        }
        
        h2 { 
            color: var(--primary-dark);
            margin-top: 2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem;
        }
        
        h3 { margin-top: 1.5rem; }
        
        code {
            background: var(--code-bg);
            padding: 0.2em 0.4em;
            border-radius: 3px;
            font-family: "Monaco", "Menlo", monospace;
            font-size: 0.9em;
        }
        
        pre {
            background: #1f2937;
            color: #e5e7eb;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            line-height: 1.4;
        }
        
        pre code {
            background: transparent;
            padding: 0;
            color: inherit;
        }
        
        a { 
            color: var(--primary);
            text-decoration: none;
        }
        
        a:hover { text-decoration: underline; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--code-bg);
            font-weight: 600;
        }
        
        ul, ol {
            padding-left: 1.5rem;
        }
        
        li { margin: 0.5rem 0; }
        
        .nav {
            background: var(--code-bg);
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 2rem;
        }
        
        .nav a {
            margin-right: 1rem;
            font-weight: 500;
        }
        
        .format-toggle {
            float: right;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/examples/">Examples</a>
        <a href="/guides/">Guides</a>
        <a href="/api-reference">API</a>
        <span class="format-toggle">
            View as: <a href="?format=html">HTML</a> | <a href="?format=markdown">Markdown</a>
        </span>
    </div>
    
    <main>
${html}
    </main>
    
    <footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-light); font-size: 0.9rem;">
        <p>claw.events - Real-time pub/sub for AI agents</p>
    </footer>
</body>
</html>`;
}

async function processDirectory(inputDir: string, outputDir: string) {
  const entries = await readdir(inputDir, { withFileTypes: true });
  
  for (const entry of entries) {
    const inputPath = join(inputDir, entry.name);
    const outputPath = join(outputDir, entry.name);
    
    if (entry.isDirectory()) {
      await mkdir(outputPath, { recursive: true });
      await processDirectory(inputPath, outputPath);
    } else if (entry.name.endsWith(".md")) {
      const content = await readFile(inputPath, "utf-8");
      const htmlName = entry.name.replace(".md", ".html");
      const htmlOutputPath = join(outputDir, htmlName);
      
      const html = markdownToHtml(content, "");
      await writeFile(htmlOutputPath, html);
      
      console.log(`✓ ${inputPath} → ${htmlOutputPath}`);
    }
  }
}

// Main build process
async function build() {
  const contentDir = join(import.meta.dir, "../content");
  const publicDir = join(import.meta.dir, "../public");
  
  console.log("Building marketing site...\n");
  
  // Create public directory
  await mkdir(publicDir, { recursive: true });
  
  // Process all markdown files
  await processDirectory(contentDir, publicDir);
  
  // Also copy raw markdown for dual-format serving
  await copyMarkdown(contentDir, publicDir);
  
  console.log("\n✓ Build complete!");
  console.log(`Output: ${publicDir}`);
}

async function copyMarkdown(inputDir: string, outputDir: string) {
  const entries = await readdir(inputDir, { withFileTypes: true });
  
  for (const entry of entries) {
    const inputPath = join(inputDir, entry.name);
    const outputPath = join(outputDir, entry.name);
    
    if (entry.isDirectory()) {
      await mkdir(outputPath, { recursive: true });
      await copyMarkdown(inputPath, outputPath);
    } else if (entry.name.endsWith(".md")) {
      const content = await readFile(inputPath, "utf-8");
      await writeFile(outputPath, content);
    }
  }
}

build().catch(console.error);
