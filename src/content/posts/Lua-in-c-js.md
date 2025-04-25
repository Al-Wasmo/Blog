---
title: Lua in both c/js
published: 2025-04-23
description: ''
image: ''
tags: [lua]
category: 'Coding'
draft: true
lang: ''
---

while i was building some js [project](http://github.com/al-wasmo/mobile-WYSIWYG), i needed to integrate lua in it so i looked online for resources and libaries that allow to run lua on the web, and i found an old project called [fengari](https://github.com/fengari-lua/fengari).    
its was prefect, but when i looked for writen examples for writing lua code with other language i didnt find much and thats needed for beginers like me, since lua using the stack for passing args and running functions.... aka everything and thats quite the new consept for me.

anyhow, this blog aims to give a simple intro to using fengrari, first of all huge credits to `Dave Poo` for his youtubue series [Embedding Lua in C++](https://www.youtube.com/watch?v=xrLQ0OXfjaI&list=PLLwK93hM93Z3nhfJyRRWGRXHaXgNX0Itk&index=1), i will be translating what he did to js but if you want a video format and a better quality explanationso watch him.    

