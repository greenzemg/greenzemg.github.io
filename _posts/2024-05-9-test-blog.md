---
layout: post
title:  A sample website for the al-folio theme
date: 2024-05-09 22:25:00
description: I am trying to check how the blog post works 
tags: formatting diagrams
categories: sample-posts
tikzjax: true
---
This is an example post with TikZ code. TikZJax converts script tags (containing TikZ code) into SVGs.

<script type="text/tikz">
\begin{tikzpicture}
    \draw[red,fill=black!60!red] (0,0) circle [radius=1.5];
    \draw[green,fill=black!60!green] (0,0) circle [x radius=1.5cm, y radius=10mm];
    \draw[blue,fill=black!60!blue] (0,0) circle [x radius=1cm, y radius=5mm, rotate=30];
\end{tikzpicture}
</script>